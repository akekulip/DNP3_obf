#!/usr/bin/env python3
"""Build a standalone plain-English report from the frozen matched-grid evidence."""
from __future__ import annotations

import json
import math
import csv
import sys
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
from reportlab.platypus import (BaseDocTemplate, Frame, Image, PageBreak,
    PageTemplate, Paragraph, Spacer, Table, TableStyle, KeepTogether)

OUT = Path(__file__).resolve().parent
DIAG = OUT.parent
RESULTS = DIAG.parent
sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
import evaluate_level_attack as level_attack
POLICIES = [f'da{x}_gap1_joint_amp0p5' for x in (5, 10, 15, 20)]
OPS = ('READ', 'SELECT', 'OPERATE')
COLORS = {'READ': '#0072B2', 'SELECT': '#D55E00', 'OPERATE': '#009E73'}


def load_json(p):
    return json.loads(p.read_text())


def fmt(x, n=2):
    return f'{x:.{n}f}'


def attack_winner(result, task, scenario, pool):
    records = result['tasks'][task]['records']
    eligible = [r for r in records if r['scenario'] == scenario and r['pool'] == pool
                and r['feature'] in {'clrt', 'ack_clrt'}]
    if not eligible:
        raise ValueError(f'missing {task}/{scenario}/pool={pool}')
    return max(eligible, key=lambda r: r['mean_accuracy'])


def make_stage_diagram(path):
    fig, ax = plt.subplots(figsize=(9.8, 4.0))
    ax.set_xlim(0, 9.8); ax.set_ylim(0, 4.0); ax.axis('off')
    stage_text = [
        ('0', 'Classify packet\nand session'),
        ('1', 'Update trackers;\nselect timing draw'),
        ('2', 'Authorize response;\nbuild deadlines'),
        ('3', 'Select deadline\ninputs for checks'),
        ('4', 'Decode state; check\nrelease deadlines'),
        ('5', 'Choose forward, hold,\nblock, or drop'),
        ('6', 'Commit result; set\nport and queue'),
    ]
    width,height,gap=2.0,.92,.31
    positions=[(.35,2.35),(2.74,2.35),(5.13,2.35),(7.52,2.35),
               (7.52,.72),(5.13,.72),(2.74,.72)]
    for i, ((num, label),(x,y)) in enumerate(zip(stage_text,positions)):
        box = FancyBboxPatch((x, y), width, height, boxstyle='round,pad=.04,rounding_size=.08',
            facecolor='#EDF3F8' if i not in (5, 6) else '#E5F2EE', edgecolor='#3D596B', linewidth=1)
        ax.add_patch(box)
        ax.text(x+width/2, y+height-.2, f'STAGE {num}', ha='center', va='center', fontsize=8, weight='bold')
        ax.text(x+width/2, y+.33, label, ha='center', va='center', fontsize=8, linespacing=1.25)
    for i in range(3):
        x,y=positions[i]
        ax.add_patch(FancyArrowPatch((x+width+.02,y+height/2),(positions[i+1][0]-.02,y+height/2),
            arrowstyle='-|>',mutation_scale=10,color='#566B78',linewidth=1))
    ax.add_patch(FancyArrowPatch((8.52,2.3),(8.52,1.72),arrowstyle='-|>',mutation_scale=10,color='#566B78',linewidth=1))
    for i in (4,5):
        x,y=positions[i]
        ax.add_patch(FancyArrowPatch((x-.02,y+height/2),(positions[i+1][0]+width+.02,y+height/2),
            arrowstyle='-|>',mutation_scale=10,color='#566B78',linewidth=1))
    ax.text(4.9, 3.78, 'Seven match-action stages: a simplified view of the compiled ingress path',
            ha='center', fontsize=12, weight='bold')
    ax.text(4.9, 3.47, 'Parser first. A packet uses only the tables needed for its class; independent checks may share a stage.',
            ha='center', fontsize=8)
    ax.text(4.9, .25, 'The stage count is a compiler placement result. Every loopback pass re-enters this pipeline.',
            ha='center', fontsize=8, color='#394D59')
    fig.savefig(path, dpi=260, bbox_inches='tight'); plt.close(fig)


def make_queue_diagram(path):
    fig, ax = plt.subplots(figsize=(10.0, 5.05))
    ax.set_xlim(0, 10.0); ax.set_ylim(0, 5.05); ax.axis('off')
    def box(x, y, w, h, text, color='#EDF3F8', fs=8):
        patch = FancyBboxPatch((x,y),w,h,boxstyle='round,pad=.04,rounding_size=.08',
            facecolor=color,edgecolor='#415968',linewidth=1)
        ax.add_patch(patch); ax.text(x+w/2,y+h/2,text,ha='center',va='center',fontsize=fs,linespacing=1.2)
    def arrow(a,b,label='',color='#50636E',rad=0):
        ax.add_patch(FancyArrowPatch(a,b,arrowstyle='-|>',mutation_scale=10,linewidth=1,
            color=color,connectionstyle=f'arc3,rad={rad}'))
        if label:
            ax.text((a[0]+b[0])/2,(a[1]+b[1])/2+.10,label,ha='center',fontsize=7,color=color,
                bbox=dict(facecolor='white',edgecolor='none',pad=1))
    box(.25,3.75,1.45,.8,'Master\n(dp9)', '#F8F2E7',9)
    box(4.05,3.75,2.0,.8,'Tofino ingress\n7 match-action stages',fs=9)
    box(8.3,3.75,1.45,.8,'Outstation\n(dp64)', '#F8F2E7',9)
    arrow((1.7,4.32),(4.05,4.32),'requests to relay')
    arrow((4.05,4.00),(1.7,4.00),'ACK/response to master')
    arrow((6.05,4.32),(8.3,4.32),'forward to relay · qid 0',color='#0072B2')
    arrow((8.3,4.00),(6.05,4.00),'relay packets · qid 0',color='#0072B2')
    box(.7,1.8,4.0,1.05,'dp8 loopback · ACK and response queues\nACK blocker qid7 > held ACK qid6\nresponse blocker qid5 > held response qid4\nDequeued packets return to ingress', '#E8F0F7',7.6)
    box(5.3,1.8,4.0,1.05,'dp10 loopback · OPERATE queues\nOPERATE blocker qid3 > held OPERATE qid2\nIndependent traffic-manager scheduler\nDequeued packets return to ingress', '#E8F0F7',7.6)
    # Paired arrows show queue admission and loopback re-entry; labels live in the queue boxes
    # so they do not collide with the diagonal return paths.
    arrow((4.2,3.72),(4.05,2.92),rad=.02)
    arrow((4.5,2.92),(5.05,3.72),rad=.02)
    arrow((5.9,3.72),(6.0,2.92),rad=-.02)
    arrow((6.3,2.92),(5.65,3.72),rad=-.02)
    ax.text(5.0,4.88,'Packet flow and traffic-manager queues',ha='center',fontsize=11,weight='bold')
    ax.text(5.0,.95,'A looped packet is parsed and classified again. Higher-priority blocker queues keep original ACKs, responses, and OPERATE packets resident until release.',
            ha='center',va='center',fontsize=8,color='#394D59',wrap=True)
    ax.text(5.0,.42,'Separate dp8 and dp10 schedulers prevent ACK/response blocker traffic from starving OPERATE release.',
            ha='center',va='center',fontsize=8,color='#394D59')
    fig.savefig(path,dpi=260,bbox_inches='tight'); plt.close(fig)


def make_cover_plot(report, path):
    fig, axes = plt.subplots(1,2,figsize=(9.8,3.0))
    for op in OPS:
        coverage=[]; overhead=[]
        for name in POLICIES:
            p=report['policies'][name]
            coverage.append(100*p['coverage'][op]['estimated_joint_ack_response_availability'])
            overhead.append(p['timing'][op]['added_pooled_median_ms'])
        axes[0].plot((5,10,15,20),coverage,marker='o',linewidth=1.3,color=COLORS[op],label=op)
        axes[1].plot((5,10,15,20),overhead,marker='o',linewidth=1.3,color=COLORS[op],label=op)
    for ax in axes:
        ax.set_xticks((5,10,15,20));ax.set_xlabel('Configured $D_A$ center (ms; $D_R$ center = 1 ms)');ax.grid(axis='y',color='.88')
        ax.spines[['top','right']].set_visible(False)
    axes[0].set_ylabel('Estimated joint ACK/response coverage (%)');axes[0].set_ylim(70,101)
    axes[1].set_ylabel('Added pooled median latency (ms)');axes[1].set_ylim(bottom=0)
    axes[0].legend(frameon=False,ncol=3,fontsize=7,loc='lower right')
    axes[1].legend(frameon=False,ncol=3,fontsize=7,loc='upper left')
    fig.tight_layout();fig.savefig(path,dpi=260,bbox_inches='tight');plt.close(fig)


def make_variation_plot(report,path):
    fig,axes=plt.subplots(2,2,figsize=(8.8,5.0),sharex=True)
    delays=(5,10,15,20)
    metrics=[('ack_ms','sd_ms','Measured request-to-ACK standard deviation (ms)'),
             ('clrt_ms','sd_ms','Measured ACK-to-response CLRT standard deviation (ms)'),
             ('ack_ms','variance_ms2','Measured request-to-ACK variance (ms²)'),
             ('clrt_ms','variance_ms2','Measured ACK-to-response CLRT variance (ms²)')]
    for ax,(measure,key,title) in zip(axes.flat,metrics):
        for op in OPS:
            vals=[report['policies'][name]['timing'][op][measure][key] for name in POLICIES]
            ax.plot(delays,vals,marker='o',markersize=3,color=COLORS[op],linewidth=1,label=op)
        ax.set_title(title,fontsize=9);ax.set_xticks(delays);ax.grid(axis='y',color='.88')
        ax.set_xlabel('Configured $D_A$ center (ms)',fontsize=8)
        ax.set_ylabel('SD (ms)' if key == 'sd_ms' else 'Variance (ms$^2$; log scale)',fontsize=8)
        ax.spines[['top','right']].set_visible(False)
        if 'variance' in key: ax.set_yscale('log')
        if ax in axes[0]: ax.legend(frameon=False,ncol=3,fontsize=7,loc='best')
    fig.tight_layout();fig.savefig(path,dpi=260,bbox_inches='tight');plt.close(fig)


def make_confusion_figure(scenario, path, title, pool=20):
    fig, axes = plt.subplots(2,4,figsize=(10,4.35))
    for row,task in enumerate(('three_class','read_select')):
        for col,(da,name) in enumerate(zip((5,10,15,20),POLICIES)):
            result=load_json(RESULTS/name/'final/attacks_heldout.json')
            winner=attack_winner(result,task,scenario,pool)
            cm=winner['confusion_matrix'];labels=winner['class_order'];ax=axes[row,col]
            ax.imshow(cm,cmap='Blues',interpolation='nearest')
            maximum=max(max(x) for x in cm)
            for i in range(len(labels)):
                for j in range(len(labels)):
                    ax.text(j,i,str(cm[i][j]),ha='center',va='center',fontsize=6,
                        color='white' if cm[i][j]>.55*maximum else '#222')
            ax.set_xticks(range(len(labels)),labels,rotation=30,ha='right',fontsize=5)
            ax.set_yticks(range(len(labels)),labels,fontsize=5)
            ax.set_title(f'D_A={da} ms; BA={winner["mean_accuracy"]:.3f}',fontsize=7)
            if col==0: ax.set_ylabel('True operation',fontsize=6)
            if row==1: ax.set_xlabel('Predicted operation',fontsize=6)
    fig.suptitle(title,fontsize=10,y=.99);fig.tight_layout(rect=(0,0,1,.95))
    fig.savefig(path,dpi=260,bbox_inches='tight');plt.close(fig)


def make_request_gap_plot(path):
    transactions=list(csv.DictReader((RESULTS/'final/primarytransactions.csv').open()))
    fig,ax=plt.subplots(figsize=(7.2,3.2))
    for op in OPS:
        values=[float(r['request_gap_ms']) for r in transactions
            if r['arm']=='obfuscated' and r['policy_name']=='da10_gap1_joint_amp0p5'
            and r['txn_class']==op and int(r['replicate'])>=40
            and r.get('request_gap_ms') not in ('',None)]
        x=sorted(values);y=[(i+1)/len(x) for i in range(len(x))]
        ax.plot(x,y,label=f'{op} (n={len(x):,})',color=COLORS[op],linewidth=1)
    ax.set_xlabel('Time since preceding request (ms)');ax.set_ylabel('Held-out cumulative fraction')
    ax.set_title('Request gaps at D_A = 10 ms (held-out rounds)',fontsize=9)
    ax.grid(axis='y',color='.88');ax.spines[['top','right']].set_visible(False)
    ax.legend(frameon=False,ncol=3,fontsize=7)
    fig.tight_layout();fig.savefig(path,dpi=260,bbox_inches='tight');plt.close(fig)


def request_gap_rows():
    rows=list(csv.DictReader((DIAG/'request_gap_attack_inventory.csv').open()))
    output=[['D_A','READ/SELECT BA\n(READ, SELECT recall)','Three-class BA\n(READ, SELECT, OPERATE recall)']]
    for da,name in zip((5,10,15,20),POLICIES):
        cells=[]
        for task in ('read_select','three_class'):
            candidates=[r for r in rows if r['policy']==name and r['task']==task
                        and int(r['pool'])==20 and r['feature']=='request_gap']
            w=max(candidates,key=lambda r:float(r['accuracy']))
            recall=[100*float(x) for x in w['class_recall'].split('|')]
            cells.append(f"{float(w['accuracy']):.3f} ({', '.join(f'{x:.1f}%' for x in recall)})")
        output.append([str(da),*cells])
    return output


def styles():
    s=getSampleStyleSheet()
    s.add(ParagraphStyle(name='TitleX',parent=s['Title'],fontName='Helvetica-Bold',fontSize=24,leading=29,
        alignment=TA_LEFT,textColor=colors.HexColor('#1D3442'),spaceAfter=12))
    s.add(ParagraphStyle(name='SubX',parent=s['Normal'],fontSize=12,leading=17,textColor=colors.HexColor('#425765'),spaceAfter=13))
    s.add(ParagraphStyle(name='H1X',parent=s['Heading1'],fontName='Helvetica-Bold',fontSize=17,leading=21,
        textColor=colors.HexColor('#17384A'),spaceBefore=5,spaceAfter=9,keepWithNext=True))
    s.add(ParagraphStyle(name='H2X',parent=s['Heading2'],fontName='Helvetica-Bold',fontSize=11.5,leading=15,
        textColor=colors.HexColor('#1C5268'),spaceBefore=7,spaceAfter=4,keepWithNext=True))
    s.add(ParagraphStyle(name='BodyX',parent=s['BodyText'],fontSize=9.2,leading=13,spaceAfter=6))
    s.add(ParagraphStyle(name='SmallX',parent=s['BodyText'],fontSize=7.4,leading=10,spaceAfter=4,textColor=colors.HexColor('#394D59')))
    s.add(ParagraphStyle(name='GlossaryX',parent=s['BodyText'],fontSize=7.2,leading=9,spaceAfter=0))
    s.add(ParagraphStyle(name='GlossaryTermX',parent=s['GlossaryX'],fontName='Helvetica-Bold'))
    s.add(ParagraphStyle(name='CalloutX',parent=s['BodyText'],fontName='Helvetica-Bold',fontSize=10.2,leading=14,
        backColor=colors.HexColor('#EEF5F2'),borderColor=colors.HexColor('#72A394'),borderWidth=.7,
        borderPadding=8,spaceBefore=5,spaceAfter=9))
    return s


def p(text, sty): return Paragraph(text, sty)


def table(data, widths, font=7.5, repeat=1):
    t=Table(data,colWidths=widths,repeatRows=repeat,hAlign='LEFT')
    t.setStyle(TableStyle([
        ('BACKGROUND',(0,0),(-1,0),colors.HexColor('#DCE8ED')),
        ('TEXTCOLOR',(0,0),(-1,0),colors.HexColor('#17384A')),
        ('FONTNAME',(0,0),(-1,0),'Helvetica-Bold'),('FONTNAME',(0,1),(-1,-1),'Helvetica'),
        ('FONTSIZE',(0,0),(-1,-1),font),('LEADING',(0,0),(-1,-1),font+2),
        ('GRID',(0,0),(-1,-1),.35,colors.HexColor('#B9C6CC')),
        ('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LEFTPADDING',(0,0),(-1,-1),5),
        ('RIGHTPADDING',(0,0),(-1,-1),5),('TOPPADDING',(0,0),(-1,-1),4),('BOTTOMPADDING',(0,0),(-1,-1),4),
        ('ROWBACKGROUNDS',(0,1),(-1,-1),[colors.white,colors.HexColor('#F6F8F9')]),
    ])); return t


def footer(canvas, doc):
    canvas.saveState(); w,h=letter
    canvas.setStrokeColor(colors.HexColor('#C6D1D6'));canvas.line(.65*inch,.52*inch,w-.65*inch,.52*inch)
    canvas.setFont('Helvetica',7);canvas.setFillColor(colors.HexColor('#637781'))
    canvas.drawString(.68*inch,.34*inch,'Seven-stage timing defense · matched delay-grid explainer · 27 September 2026')
    canvas.drawRightString(w-.68*inch,.34*inch,f'Page {doc.page}')
    canvas.restoreState()


def build():
    OUT.mkdir(parents=True,exist_ok=True)
    report=load_json(RESULTS/'grid_report.json')
    attacks=load_json(RESULTS/'grid_attacks.json')
    audit=load_json(RESULTS/'independent_audit.json')
    _, level_policies = level_attack.load(RESULTS/'final/measurements.json',
        RESULTS/'final/primarytransactions.csv', inspect_only=True)
    measurement_manifest = load_json(RESULTS/'final/measurements.json')
    d_r_visibility = []
    d_r_variance = []
    for da, name in zip((5,10,15,20), POLICIES):
        rows, levels, _ = level_policies[name]
        match = level_attack.inference_audit(rows, levels)['clrt_ms']
        dr_levels = ', '.join(f"{x:.3f}" for x in levels['gap_ms'])
        d_r_visibility.append([str(da), dr_levels,
            f"{100*match['selection_agreement_within_1us']:.2f}%",
            f"{match['n']:,}"])
        plan_paths = [Path(path) for path in measurement_manifest['inputs_sha256']
            if Path(path).parent.name == 'plans' and Path(path).stem == name]
        if len(plan_paths) != 1:
            raise ValueError(f'expected one validated timing plan for {name}')
        plan_path = plan_paths[0]
        if level_attack.sha(plan_path) != measurement_manifest['inputs_sha256'][str(plan_path)]:
            raise ValueError(f'timing plan hash mismatch for {name}')
        plan = load_json(plan_path)
        weighted = [(float(entry['gap_ms']), (entry['high']-entry['low']+1)/256.0)
            for entry in plan['entries']]
        weight_sum = sum(weight for _, weight in weighted)
        if not math.isclose(weight_sum, 1.0, abs_tol=1e-12):
            raise ValueError(f'D_R choice probabilities do not sum to one for {name}')
        mean = sum(value*weight for value, weight in weighted)
        variance = sum(weight*(value-mean)**2 for value, weight in weighted)
        d_r_variance.append([str(da), dr_levels, f'{mean:.6f}',
            f'{math.sqrt(variance):.6f}', f'{variance:.6f}'])
    if len({row[-1] for row in d_r_variance}) != 1:
        raise ValueError('configured D_R variance unexpectedly changes across D_A settings')
    plots={
        'stage':OUT/'seven_stage_overview.png',
        'queues':OUT/'queue_packet_flow.png',
        'tradeoff':OUT/'coverage_latency_by_delay.png',
        'static_cm':OUT/'static_confusions_pool20.png',
        'gap':OUT/'request_gap_ecdf_da10.png',
        'variation':OUT/'variance_and_standard_deviation.png',
    }
    make_stage_diagram(plots['stage']);make_queue_diagram(plots['queues']);make_cover_plot(report,plots['tradeoff'])
    make_confusion_figure('fixed_on_obfuscated',plots['static_cm'],'Static attacker: trained on Timing OFF, tested on protected traffic')
    make_request_gap_plot(plots['gap'])
    make_variation_plot(report,plots['variation'])
    sty=styles(); story=[]
    story += [Spacer(1,.5*inch),p('What the seven-stage timing defense does',sty['TitleX']),
        p('A plain-English guide to the Tofino pipeline, measured delay and packet coverage, and the attackers tested at four D<sub>A</sub> settings.',sty['SubX']),
        p('Prepared from the completed matched hardware grid: D<sub>A</sub> = 5, 10, 15, and 20 ms; D<sub>R</sub> (the chosen response-delay/CLRT target) centered at 1 ms with ±0.5 ms choices; 100 rounds; 240,000 primary exchanges.',sty['BodyX']),
        Spacer(1,10),Image(str(plots['tradeoff']),width=7.05*inch,height=2.16*inch),
        p('The trade-off is visible: larger D<sub>A</sub> improves the estimated chance that the original ACK and response are ready before release, while adding more latency. These plots vary D<sub>A</sub> while holding the D<sub>R</sub> center at 1 ms (with the same ±0.5 ms choices). None of the four policies passes the study’s adaptive ACK/CLRT classifier criterion.',sty['CalloutX']),
        p('This report describes the measured implementation and proposes follow-up design changes. It does not modify the P4 implementation or the paper.',sty['BodyX']),
        PageBreak()]

    story += [p('1. What happens in the seven ingress stages',sty['H1X']),
        p('The switch first parses the Ethernet, IP, TCP, and DNP3 fields. The ingress match-action pipeline then identifies whether a packet is a master request, relay acknowledgment, relay response, generated blocker, or a packet returning from an internal loopback. It reads and updates small state registers to keep packets from unrelated sessions or old transactions from being mistaken for the current one.',sty['BodyX']),
        p('A simple way to follow one exchange is: the master sends a request; the switch records enough context to recognize the exchange; the outstation returns an acknowledgment and later the application response; the switch holds and releases these packets according to the selected timing settings. A packet returning from the internal loopback is checked again so the switch can decide whether its wait is over. The stage diagram groups these decisions by job; it is not a packet-by-packet trace.',sty['BodyX']),
        Image(str(plots['stage']),width=7.1*inch,height=2.95*inch),
        p('The picture groups work by purpose; it is not a claim that every packet executes every table. Tofino can place independent tables in the same stage. The final randomized build has seven ingress stages, zero egress match-action stages, and a seven-stage critical dependency path. The published placement evidence for the closely corresponding randomized candidate reports 76 allocated tables.',sty['SmallX']),
        table([
            ['Stage','Plain-English role'],
            ['0','Parse-derived class and session state are available; read parameters and transaction trackers.'],
            ['1','Check expected TCP/transaction state and select the configured per-request timing draw.'],
            ['2','Authorize a response and build the timing candidates needed for this packet.'],
            ['3','Select deadline operands for the checks that follow.'],
            ['4','Decode transaction state and check whether ACK/response release conditions are met.'],
            ['5','Choose the fresh-packet or dequeued-packet outcome, including forward, hold, blocker loop, or drop.'],
            ['6','Commit the selected action: set egress port and queue or drop, and record the terminal outcome.'],
        ],[.62*inch,6.25*inch],font=7.2),
        p('The named placement anchors are confirmed in the P4/compiler evidence: response authorization at stage 2, deadline selection at 3, state decode at 4, and the single terminal commit table at 6. Stage numbers are zero-based in the compiler report.',sty['SmallX']),
        p('“Seven stages” means seven sequential ingress processing stages allocated by the Tofino compiler. It does not mean the program contains only seven operations or seven tables: many tables can run in parallel within one stage, and packets of different types can follow different table paths. The compiler placement is evidence about the cost of this build; it does not by itself say how much network delay a packet experiences.',sty['BodyX']),
        PageBreak()]

    story += [p('2. Queues and packet flow',sty['H1X']),
        p('A packet that is ready to leave is forwarded through queue 0. A packet that must wait is placed in a traffic-manager queue on an internal loopback port. When the traffic manager dequeues it, it returns through ingress, where the switch rechecks its state and either keeps it blocked or releases it. The original packet bytes remain queue-resident; synthetic blocker packets create the queue occupancy that holds them.',sty['BodyX']),
        Image(str(plots['queues']),width=7.12*inch,height=3.63*inch),
        p('On dp8, higher-priority queue IDs make ACK blockers (qid 7) drain before the held ACK (qid 6), and response blockers (qid 5) drain before the held response (qid 4). The ACK and response share this scheduling domain, with ACK ahead of response. OPERATE uses a second loopback and scheduler on dp10: blocker qid 3 precedes held OPERATE qid 2. This prevents ACK/response blocker load from starving the OPERATE release domain.',sty['BodyX']),
        p('Here “blocker” means a synthetic packet used to occupy a higher-priority queue. It is not a dropped packet or an attacker packet. While blockers drain first, the real packet behind them remains queued. The queue ordering creates a wait; ingress logic tracks which packet is waiting and whether it is now eligible to leave. The queue IDs and priority relationships describe this configured scheduler.',sty['BodyX']),
        p('At a high level, the stages decide what a packet is allowed to do; the traffic manager’s queues provide the waiting. Egress and the loopback determine the next physical path. A loopback packet re-enters the ingress pipeline as a new pass.',sty['CalloutX']),
        PageBreak()]

    story += [p('3. What D<sub>A</sub> and D<sub>R</sub> mean, and how much delay they add',sty['H1X']),
        p('The mechanism uses two deadlines. D<sub>A</sub> is the selected wait after the switch receives the outstation’s original ACK; it sets when the master-facing ACK may be released. D<sub>R</sub> is the selected response delay after that ACK deadline; it sets the target interval from the released ACK to the response. The P4 timing equations are T<sub>A</sub> = t<sub>A</sub> + D<sub>A</sub> and T<sub>RESP</sub> = T<sub>A</sub> + D<sub>R</sub>. The attacker sees packet timing at the master-facing link, including the ACK-to-response interval (CLRT) that carries the selected D<sub>R</sub> choice.',sty['BodyX']),
        p('For this run, D<sub>A</sub> centers were 5, 10, 15, and 20 ms. D<sub>R</sub> was centered at 1 ms. Each has four choices across ±0.5 ms, producing 16 joint D<sub>A</sub>/D<sub>R</sub> pairs. The actual quantized D<sub>R</sub> choices were approximately 0.500, 0.833, 1.167, and 1.500 ms. The nominal response deadline is therefore about 6, 11, 16, or 21 ms after the original ACK reaches the switch—not after the master request. These are configured deadlines, not measured end-to-end latencies. Relay response time and queue drain can make the measured packet timings longer.',sty['BodyX']),
        p('This table uses all 100 rounds: 10,000 protected exchanges per operation and policy. “Total median” is measured request-to-response latency under protection. “Added median” subtracts the Timing OFF median for the same operation. The p99 is the protected request-to-response percentile. The data are master-facing; they do not directly timestamp entry into the switch queues. Classifier scores later in the report use only held-out rounds 40–99.',sty['BodyX'])]
    data=[['D_A','Operation','Protected total\nmedian (ms)','Timing OFF\nmedian (ms)','Added\nmedian (ms)','Protected\np99 (ms)','CLRT > selected D_R\n+ 1 ms']]
    for da,name in zip((5,10,15,20),POLICIES):
        for op in OPS:
            q=report['policies'][name]['timing'][op]
            data.append([str(da),op,fmt(q['rt_ms']['median_ms'],3),fmt(q['native_rt_ms']['median_ms'],3),
                fmt(q['added_pooled_median_ms'],3),fmt(q['rt_ms']['p99_ms'],3),
                f"{q['late_over_1ms']['count']}/{q['late_over_1ms']['total']} ({100*q['late_over_1ms']['fraction']:.2f}%)"])
    story += [table(data,[.45*inch,.68*inch,.9*inch,.84*inch,.78*inch,.82*inch,1.42*inch],font=6.5),Spacer(1,7),
        p('The last column is a different question from packet loss. It counts held-out replies whose measured ACK-to-response CLRT exceeds the selected D<sub>R</sub> target by more than 1 ms. Across the four delay settings the counts fall as the response window moves later, but the READ tail remains visible.',sty['SmallX']),
        p('Read the latency columns separately: “protected total median” is measured request-to-response time; “Timing OFF median” is the paired baseline for the same operation; “added median” is their difference. The p99 means 99% of observations were at or below that time and about 1% were above it. The last column counts replies whose measured CLRT exceeded the selected D<sub>R</sub> target by over 1 ms. It is not a count of lost packets or responses past the master’s application timeout.',sty['BodyX']),
        p('For a compact setting-level summary, the worst operation’s added median is 3.58, 8.56, 13.57, and 18.57 ms at D<sub>A</sub> = 5, 10, 15, and 20 ms. The corresponding worst operation p99 is 15.25, 15.29, 17.12, and 22.12 ms. “Worst” means the largest among READ, SELECT, and OPERATE for each metric.',sty['CalloutX']),
        PageBreak()]

    story += [p('4. Late responses, coverage, and actual packet loss',sty['H1X']),
        p('There were 0 missing primary responses out of 240,000 exchanges, 0 reported capture drops, and 0 TCP retransmission flags. So “missed” here does not mean that the relay failed to answer or that a packet vanished. It means the original response may arrive after the configured release point. In that case, the switch cannot send it backward in time; the response can be released as soon as it arrives, outside the intended timing window.',sty['CalloutX']),
        p('The table’s standalone “responses past D<sub>A</sub>” count compares baseline request-to-response time with the D<sub>A</sub> center. Because the P4 timer starts when the switch receives the original ACK, this simple comparison is not itself a D<sub>A</sub> deadline-miss count. The joint-coverage estimate separately compares baseline request-to-ACK and request-to-response measurements with the configured D<sub>A</sub> and combined D<sub>A</sub>+D<sub>R</sub> targets. These master-facing measurements are availability proxies, not exact switch-arrival measurements or labels on individual protected packets.',sty['BodyX'])]
    story += [p('The distinction is: a <b>lost</b> response never appeared in the capture; a <b>beyond-center baseline</b> response appeared, but its unprotected request-to-response time exceeded the D<sub>A</sub> comparison value. Because the internal D<sub>A</sub> clock starts at the original ACK, this count is not a true deadline-miss count. It is a rough way to compare settings; it does not identify which protected response escaped timing treatment.',sty['BodyX'])]
    cov=[['D_A','Operation','Timing OFF\nresponses past D_A','Fraction past\nD_A','Estimated joint\ncoverage']]
    for da,name in zip((5,10,15,20),POLICIES):
        for op in OPS:
            x=report['policies'][name]['coverage'][op]
            cov.append([str(da),op,f"{x['beyond_da_center_count']:,}/{x['native_n']:,}",
                f"{100*x['beyond_da_center_fraction']:.2f}%",f"{100*x['estimated_joint_ack_response_availability']:.2f}%"])
    story += [table(cov,[.48*inch,.70*inch,1.55*inch,1.15*inch,1.5*inch],font=7),Spacer(1,7),
        p('At 5 ms, between 17.18% and 27.67% of the 10,000 Timing OFF samples per operation are past the center. Estimated joint coverage is 79.23–86.40%, depending on operation. At 10 ms, the past-center share is 2.66–3.06% and estimated coverage is 97.46–97.86%. At 15 ms, the past-center share is 0.66–0.85% and coverage is 99.27–99.77%. At 20 ms, the past-center share is 0.04–0.61% and coverage is 99.40–99.96%.',sty['BodyX']),
        p('This availability estimate averages the measured baseline ACK and response times against all 16 quantized choices. It omits protected-path command holds and queue state. It cannot prove which protected exchanges were or were not obfuscated. No hard 99.9% coverage threshold was part of this grid.',sty['SmallX']),
        p('“Estimated joint coverage” combines the ACK and response comparisons over all 16 configured D<sub>A</sub>/D<sub>R</sub> pairs. It is calculated from paired baseline timing samples and selected targets; it is not a second hardware packet count. Since the capture observes packets at the master-facing link rather than at switch ingress, it is a rough availability comparison among settings, not a guarantee for every future workload.',sty['BodyX']),
        PageBreak()]

    story += [p('5. Variance: chosen D<sub>R</sub> and measured CLRT',sty['H1X']),
        p('Variance describes spread around an average; standard deviation is its square root and is easier to read in milliseconds. There are two different spreads here. First is the variation deliberately built into the chosen new CLRT, D<sub>R</sub>. Second is the variation in the CLRT actually measured between ACK and response packets. The measured interval includes D<sub>R</sub> plus response-arrival, queueing, and long-tail effects.',sty['BodyX']),
        p('Spread of the chosen new CLRT (D<sub>R</sub>)',sty['H2X']),
        p('This table calculates the population variance of the configured random choices, weighted by the probability of each timing-table entry. Each policy uses the same four D<sub>R</sub> choices, each with equal probability, so the D<sub>R</sub> variance is the same for all D<sub>A</sub> settings. This is the defense’s chosen-delay spread, not the attacker’s measured CLRT spread.',sty['BodyX'])]
    drdata=[['D_A center (ms)','Possible D_R choices (ms)','Mean D_R (ms)','D_R SD (ms)','D_R variance (ms²)'],*d_r_variance]
    story += [table(drdata,[1.0*inch,2.15*inch,1.0*inch,1.0*inch,1.3*inch],font=7),Spacer(1,7),
        p('The configured D<sub>R</sub> variance is about 0.138871 ms² (SD 0.372654 ms) at every D<sub>A</sub>. A smaller value would mean the randomized response target is more tightly clustered. By itself, it would not show that the measured CLRT has little spread or that an attacker cannot classify operations.',sty['CalloutX']),
        p('The plot below shows the separate, measured packet-timing spread across D<sub>A</sub> settings and operations.',sty['BodyX']),
        Image(str(plots['variation']),width=6.75*inch,height=3.65*inch),
        PageBreak(),p('Measured packet-timing variance by D<sub>A</sub> and operation',sty['H2X']),
        p('These are the protected packet observations across 100 rounds: 10,000 per operation and policy. The measured CLRT variance includes the chosen D<sub>R</sub> variation together with response-arrival and queueing behavior. This is the spread the timing-based attacker can observe. The request-to-ACK variance is shown separately because it carries the D<sub>A</sub> timing choice.',sty['BodyX'])]
    vdata=[['D_A','Operation','ACK SD\n(ms)','ACK variance\n(ms²)','CLRT SD\n(ms)','CLRT variance\n(ms²)']]
    for da,name in zip((5,10,15,20),POLICIES):
        for op in OPS:
            q=report['policies'][name]['timing'][op]
            vdata.append([str(da),op,fmt(q['ack_ms']['sd_ms'],3),fmt(q['ack_ms']['variance_ms2'],4),
                fmt(q['clrt_ms']['sd_ms'],3),fmt(q['clrt_ms']['variance_ms2'],4)])
    story += [table(vdata,[.45*inch,.78*inch,1.02*inch,1.18*inch,1.02*inch,1.25*inch],font=7),Spacer(1,6),
        p('For example, at D<sub>A</sub>=10 ms, READ CLRT has SD 2.413 ms and variance 5.824 ms² because rare long READ responses are included. SELECT has SD 0.633 ms and variance 0.400 ms²; OPERATE has SD 0.820 ms and variance 0.673 ms². Removing tails would make these numbers look smaller but would hide behavior that matters to both availability and an attacker.',sty['BodyX']),
        p('Standard deviation is easier to interpret because it is still measured in milliseconds: larger SD means individual measurements tend to sit farther from their average. Variance is SD multiplied by itself, so its unit is milliseconds squared and rare long values increase it sharply. These figures combine all configured timing choices and rounds. They include deliberate delay choices and natural packet/queue variation; they do not measure randomness alone.',sty['BodyX']),
        PageBreak()]

    story += [p('6. What the timing distributions look like',sty['H1X']),
        p('The raw plots show request-to-ACK timing and the attacker-visible ACK-to-response CLRT. The selected D<sub>A</sub> and D<sub>R</sub> choices affect those measured intervals; response arrival and queueing add variation. In the right-side plots, we subtract the nearest configured D<sub>A</sub> choice from ACK timing and the nearest configured D<sub>R</sub> choice from CLRT. This tests whether operation can still be inferred after those known timing choices are removed.',sty['BodyX']),
        Image(str(DIAG/'adaptive_raw_ecdf.png'),width=7.1*inch,height=5.25*inch),
        p('Each curve is the cumulative fraction of held-out samples at or below a timing value. Similar curves mean similar one-dimensional distributions; they do not prove that all multivariate classifiers fail.',sty['SmallX']),
        p('How to read the axes: choose a time on the horizontal axis, then read upward to a curve. The vertical value tells you what fraction of that operation’s packets arrived by that time. For example, a value of 0.8 means 8 out of 10 measured packets were at or below that time. Curves close together have similar timing for this one measurement; curves apart show a timing difference an attacker may use.',sty['BodyX']),
        p('Each row uses a different D<sub>A</sub>. In the left plots, the horizontal position includes the selected ACK wait, so the whole group moves later as D<sub>A</sub> increases. In the right plots, the horizontal position is the measured time from ACK to response; it includes the chosen D<sub>R</sub>, but also the outstation response time and queueing. The visible steps partly reflect the small set of configured delay choices. A response that arrives after its target can extend the curve to the right.',sty['BodyX']),
        p('An empirical cumulative distribution answers: at a given time on the horizontal axis, what fraction of observed packets finished by then? Curves that separate indicate that one operation tends to have faster or slower measurements. The plots show held-out data; models were trained on earlier rounds. The horizontal display trims only the most extreme 0.5% tails to keep the main curves readable. Tail counts and percentiles remain in the tables.',sty['BodyX']),
        PageBreak(),
        p('Timing after subtracting the nearest configured delay step',sty['H1X']),
        Image(str(DIAG/'adaptive_residual_ecdf.png'),width=7.1*inch,height=5.25*inch),
        p('These plots show times after subtracting the nearest configured delay step—the setting an attacker can learn. For example, if an ACK is measured near 10.10 ms and the nearest configured D<sub>A</sub> choice is 10.167 ms, the residual is about −0.067 ms. For CLRT, the nearest D<sub>R</sub> choice is subtracted in the same way. The attacker estimates the nearest choice from observed timing; it is not given the switch’s private random draw.',sty['BodyX']),
        p('The residual curves ask whether operation still leaves a recognizable pattern after the known delay is removed. They overlap strongly in many panels, but that does not mean the attacker has no signal. The measured variance table shows why: at D<sub>A</sub>=10 ms, READ CLRT has SD 2.413 ms, compared with 0.633 ms for SELECT and 0.820 ms for OPERATE. A wide READ tail can remain informative even when most of the curves overlap.',sty['BodyX']),
        p('A curve shows one feature at a time. The classifier can combine ACK and CLRT, use a nonlinear decision rule, and summarize repeated samples. In this run, the strongest adaptive three-class accuracy after subtracting the known delay was 65.4% at D<sub>A</sub>=10 ms, compared with 33.3% chance. At 15 and 20 ms it fell to 42.3% and 42.9%, but still exceeded the study’s 38.3% screening limit. So the plots help explain the distributions; the held-out classifier results decide whether the attacker was actually weakened enough.',sty['BodyX']),
        PageBreak()]

    story += [p('7. The two attacker types',sty['H1X']),
        p('<b>Static attacker.</b> It learns on Timing OFF data, then applies the same frozen classifier after timing protection is enabled. It does not adapt to the protected distribution. This asks whether the defense breaks a classifier trained before deployment.',sty['BodyX']),
        p('<b>Adaptive attacker.</b> It trains using only protected traffic. It has no Timing OFF training examples. Its inputs include observed ACK and/or CLRT intervals, which carry the selected D<sub>A</sub> and D<sub>R</sub> choices. One version also knows the configured choices and subtracts the nearest expected D<sub>A</sub> or D<sub>R</sub> value before classification. It does not receive the switch’s private per-packet selection record. This tests whether the attacker can learn the protected pattern after deployment.',sty['BodyX']),
        p('The two classification questions are READ vs SELECT and READ vs SELECT vs OPERATE. Recall is the fraction of examples of one operation that the model labels correctly. Balanced accuracy averages recall across operations so a model cannot score well just by always guessing the most common label. A random guess has expected balanced accuracy 0.50 for two labels and 0.333 for three. The study’s screening limit is chance plus 0.05: 0.55 and 0.383. Passing would mean this tested classifier is close to chance; it would not prove every possible attacker fails.',sty['BodyX']),
        p('For each setting, 40 rounds train and tune the models; 60 later rounds are held out. Five grouped folds tune choices using training rounds only. The model is then frozen before it sees test rounds. Three model families are compared: Random Forest (many decision trees), logistic regression (a linear boundary), and an RBF support-vector machine (a nonlinear boundary). Tuning checks tree leaf sizes or regularization values. The winning displayed score is the strongest result among the frozen candidate attacks, so it should be read as a conservative attacker result, not as the average of all models.',sty['BodyX']),
        p('The attacker observes the request-to-ACK interval and/or the master-facing ACK-to-response CLRT. The latter is where the selected D<sub>R</sub> choice is visible in packet timing. For pools of 5 and 20, the evaluator summarizes repeated examples of one operation using mean, standard deviation, minimum, and maximum. Pooling tests whether repeated observations help the attacker average out random timing variation.',sty['BodyX']),
        p('The input features are observable timing quantities: request-to-ACK time, ACK-to-response time (CLRT), or both together. A pool-20 input is not one packet; it summarizes up to 20 repeated examples of one operation. This gives the attacker more evidence than one observation and assumes it can recognize or group examples from the same operation. That assumption matters: if it cannot group them, the pooled result may overstate practical capability.',sty['BodyX']),
        p('The experiment also scores request-gap features separately. This measures time between incoming requests. It is not part of the primary ACK/CLRT decision because it can reveal the workload schedule independently of the response-timing defense.',sty['CalloutX']),
        PageBreak()]

    story += [p('8. Classifier results after protection',sty['H1X']),
        p('At pool size 20, a static classifier trained on Timing OFF falls to roughly chance balanced accuracy when applied unchanged to protected ACK/CLRT timing. The adaptive classifier recovers some of that lost capability. Subtracting the nearest configured D<sub>A</sub>/D<sub>R</sub> choice often helps the adaptive attacker rather than eliminating its signal. The attacker sees these choices through measured intervals; it is not handed the switch’s private selection log. Each table entry is the strongest held-out score among the tested model choices, not their average.',sty['BodyX'])]
    for task,title in [('three_class','Three classes: READ / SELECT / OPERATE'),('read_select','Two classes: READ / SELECT')]:
        data=[[p('D_A',sty['GlossaryTermX']),p('Static:<br/>OFF→OFF',sty['GlossaryTermX']),
            p('Static:<br/>OFF→protected',sty['GlossaryTermX']),p('Adaptive:<br/>observed timing',sty['GlossaryTermX']),
            p('Adaptive:<br/>subtract D_A/D_R',sty['GlossaryTermX'])]]
        for da,name in zip((5,10,15,20),POLICIES):
            result=load_json(RESULTS/name/'final/attacks_heldout.json')
            w0=attack_winner(result,task,'fixed_on_native',20)
            ws=attack_winner(result,task,'fixed_on_obfuscated',20)
            wa=attack_winner(result,task,'adaptive_on_obfuscated',20)
            wl=attack_winner(result,task,'adaptive_on_offset_residuals',20)
            data.append([str(da),f"{w0['mean_accuracy']:.3f}",f"{ws['mean_accuracy']:.3f}",
                         f"{wa['mean_accuracy']:.3f}",f"{wl['mean_accuracy']:.3f}"])
        story += [p(title,sty['H2X']),table(data,[.60*inch,1.25*inch,1.48*inch,1.20*inch,1.48*inch],font=7),Spacer(1,7)]
    pooldata=[['D_A','Pool','3-class raw','3-class − D_A/D_R','R/S raw','R/S − D_A/D_R']]
    for da,name in zip((5,10,15,20),POLICIES):
        result=load_json(RESULTS/name/'final/attacks_heldout.json')
        for pool in (1,5,20):
            vals=[]
            for task,scenario in [('three_class','adaptive_on_obfuscated'),('three_class','adaptive_on_offset_residuals'),
                                  ('read_select','adaptive_on_obfuscated'),('read_select','adaptive_on_offset_residuals')]:
                vals.append(f"{attack_winner(result,task,scenario,pool)['mean_accuracy']:.3f}")
            pooldata.append([str(da),str(pool),*vals])
    story += [Image(str(DIAG/'adaptive_accuracy_by_pool.png'),width=7.08*inch,height=2.78*inch),
        p('Exact strongest balanced accuracy by pool size (held-out rounds)',sty['H2X']),
        table(pooldata,[.55*inch,.55*inch,1.18*inch,1.32*inch,1.0*inch,1.16*inch],font=6.5),Spacer(1,7),
        p('In the three-class task, the strongest adaptive results after subtracting the known delay step at pool size 20 are 0.553, 0.654, 0.423, and 0.429 for D<sub>A</sub>=5, 10, 15, and 20 ms. The approximate simultaneous 97.5% upper confidence limits are 0.607, 0.708, 0.477, and 0.482. Each score is above its 0.383 acceptance limit. In READ/SELECT, the best scores are 0.562, 0.588, 0.562, and 0.555; all exceed the 0.55 limit (upper limits 0.627, 0.653, 0.627, and 0.620). These upper limits express uncertainty in the estimates and account for comparing several tested settings and attacks. None of the four policies passes.',sty['CalloutX']),
        p('At 10 ms, the three-class model recalls 46.3% of READ, 60.0% of SELECT, and 90.0% of OPERATE. It is not equally effective across classes. At 15 ms, the READ/SELECT model’s 0.562 balanced accuracy comes from 14.0% READ recall and 98.3% SELECT recall; the headline score alone would hide this imbalance.',sty['BodyX']),
        p('A three-class score of 0.654 means the average recall across READ, SELECT, and OPERATE is 65.4%; it does not mean each operation is recognized 65.4% of the time. Compare the score with chance and the screening limit, then check per-operation recall and the confusion matrix. None of the four settings demonstrates the target against all tested timing attackers.',sty['BodyX']),
        PageBreak()]

    story += [p('9. Confusion matrices: which labels are mixed up?',sty['H1X']),
        p('The static attacker does lose the ability to classify protected timing with its old model. However, its confusion matrix shows that “near chance” often means the model collapses toward one label. The classifier still makes strongly biased predictions, so its behavior should be read from class recalls as well as its overall balanced accuracy.',sty['BodyX']),
        Image(str(plots['static_cm']),width=7.1*inch,height=3.1*inch),
        p('The first table in Section 8 gives the strongest frozen static candidate on Timing OFF and the strongest transferred static result on protected timing. Hyperparameter selection occurs inside the training data; the separately reported scenario maxima need not use identical settings. The comparison shows how a static attacker can fail after the timing distribution shifts.',sty['SmallX']),
        p('In each matrix, a row is the operation that really occurred and a column is the operation guessed by the model. Correct guesses lie on the diagonal. Off-diagonal counts show which operations are confused. A model that guesses almost everything as one operation may have low balanced accuracy, but it is not behaving like a fair random guess; it has a systematic bias.',sty['BodyX']),
        PageBreak(),
        p('Adaptive confusion matrices: which labels are mixed up?',sty['H1X']),
        p('Rows are the true operation, columns are the predicted operation. A strong diagonal means correct predictions. For each setting and task, this selects the stronger of the measured-time and known-step adaptive ACK/CLRT attacks at pool size 20. Each count represents a group of up to 20 samples of the same operation rather than one packet.',sty['BodyX']),
        Image(str(DIAG/'adaptive_confusions_pool20.png'),width=7.12*inch,height=3.63*inch),
        p('At D<sub>A</sub>=10 ms, the model recognizes OPERATE often, while many READ and SELECT samples are confused. At 15 ms in the two-class task, it predicts SELECT for almost every true SELECT but misses most READs. That is why the report gives both confusion matrices and balanced accuracy.',sty['BodyX']),
        p('“Static near chance” also requires care: the static classifier frequently collapses to a single predicted class. Low balanced accuracy means this tested classifier does not recover the classes evenly; it does not mean its predictions are uniformly random.',sty['SmallX']),
        PageBreak(),
        p('10. What pooled feature clusters show',sty['H1X']),
        p('Each point represents a held-out pooled signature. Color is the true operation; circles are correctly classified and x marks are errors. PCA compresses the original feature vector into two axes, fitted on training data and then applied to held-out data. The original classifier may use dimensions that the plot cannot show.',sty['BodyX']),
        Image(str(DIAG/'adaptive_clusters_pool20.png'),width=7.12*inch,height=6.25*inch),
        p('The separated READ outliers in some panels may help explain why pooling improves performance, but the projection is descriptive. Use the confusion matrices and held-out scores—not visual separation in PCA—as the evidence of classifier capability.',sty['SmallX']),
        p('PCA (principal component analysis) takes many measured features and projects them onto two summary axes so they can be drawn on a page. It keeps some large patterns but can discard smaller differences. Points that overlap here could still be separable in the original feature space; visible separation alone does not prove generalization. Held-out predictions are the direct test.',sty['BodyX']),
        PageBreak()]

    story += [p('11. Which features still leak operation information?',sty['H1X']),
        p('<b>The attacker sees the chosen D<sub>R</sub> through CLRT.</b> D<sub>R</sub> is the selected response-delay target after the ACK deadline. The attacker observes the master-facing time between the released ACK and response; this measured CLRT contains the D<sub>R</sub> choice, plus response-arrival and queueing variation. In this run, D<sub>R</sub> could be approximately 0.500, 0.833, 1.167, or 1.500 ms. The attacker’s classifier receives the measured CLRT, not an internal switch register or the run’s private selection log.',sty['BodyX']),
        table([['D_A center (ms)','Possible D_R choices (ms)','Nearest choice agrees with selected D_R','Samples']]+d_r_visibility,
            [1.0*inch,1.45*inch,2.45*inch,.8*inch],font=7),Spacer(1,5),
        p('The agreement column is a separate audit: after the run, we compared each selected D<sub>R</sub> recorded in the measurement log with the nearest allowed value inferred from observed CLRT. It matched within 1 microsecond for 87.72%, 97.98%, 99.56%, and 99.82% of the 30,000 samples at D<sub>A</sub>=5, 10, 15, and 20 ms. The log’s exact chosen value is used only for this check; it is not supplied to the classifier. This shows how much of the selected D<sub>R</sub> is exposed by the observed interval, while preserving the distinction between chosen D<sub>R</sub> and measured CLRT.',sty['BodyX']),
        p('<b>The attacker can also learn the configured timing steps.</b> The raw ACK interval carries the selected D<sub>A</sub> choice, and CLRT carries the selected D<sub>R</sub> choice. One adaptive test subtracts the nearest configured choice from each observed interval; it does not receive the exact random draw as a feature. Each fresh request selects one of 16 joint D<sub>A</sub>/D<sub>R</sub> pairs using a byte from the packet’s pseudo-random number generator (PRNG). That same byte also selects the OPERATE hold value, so these choices are not independent. The stronger results after subtraction show that choosing randomly from a small set of known delays is not enough by itself.',sty['BodyX']),
        p('<b>Response timing still carries operation clues.</b> Even after subtracting the expected delay step, ACK and response times still differ somewhat by operation and include occasional long delays. Combining repeated measurements helps the attacker find those differences. At D<sub>A</sub>=10 ms, the strongest three-class result using measured times rises from 0.456 with one sample to 0.516 with groups of 20; after subtracting the known step, it rises from 0.447 to 0.654. “Pool 20” means the classifier combines summary statistics from up to 20 examples of the same operation.',sty['BodyX']),
        p('The all-round tail table shows one possible source of signal: at D<sub>A</sub>=10 ms, 2.47% of READ responses exceed their selected response target by more than 1 ms, compared with 1.55% of SELECT and 2.67% of OPERATE. At 15 and 20 ms, READ also has much larger CLRT spread than the other classes. These are class-conditioned timing differences that a pool-based model can measure. They do not fully explain the scores: D<sub>A</sub>=5 has higher late fractions but lower adaptive balanced accuracy than D<sub>A</sub>=10. The classifier is combining features and distributions, not applying a single “late packet” rule.',sty['BodyX']),
        p('<b>Queue and workload state.</b> A response’s release can depend on how much blocker traffic is ahead of it when it reaches the traffic manager. That queue state can make otherwise similar packets wait different amounts. The tested command sequences also differ: READ requests were spaced about 400 ms apart and OPERATE followed SELECT immediately. Thus response timing and the time between incoming requests can both reveal the operation. The request-gap result is separate because a response delay cannot erase a gap already observed on the incoming link.',sty['BodyX']),
        PageBreak(),
        p('<b>Request-gap channel (separate result).</b> With pools of 20, request-gap-only balanced accuracy ranges from 0.982 to 0.999 for READ/SELECT and 0.986 to 0.999 for three classes across the four settings. That is strong schedule leakage, but it is not evidence that ACK/CLRT alone reaches 0.99. The ingress request gaps were observable in the measurement location and the workload had a structured schedule.',sty['CalloutX']),
        table(request_gap_rows(),[.5*inch,2.55*inch,3.4*inch],font=6.8),Spacer(1,5),
        Image(str(plots['gap']),width=7.0*inch,height=2.45*inch),
        p('In this workload, READ requests are scheduled about 400 ms apart, while SELECT is followed by OPERATE immediately. That makes request gaps informative and shows why a downstream response timer cannot hide an incoming gap already observed by the attacker. These are operation labels from one SEL-751A, not cross-device identity results.',sty['SmallX']),
        PageBreak()]

    story += [p('12. Proposed changes to remove the remaining leakage',sty['H1X']),
        p('These are design directions, not changes to the running implementation. Each targets a different source of information found in this analysis. A response-timing fix will not automatically hide request spacing, and more delay choices will not automatically remove class-dependent queue behavior. Each idea should be tested against the same attacker and latency measurements before acceptance.',sty['BodyX']),
        p('<b>1. Remove timing dependence on queue occupancy.</b> The current mechanism uses higher-priority blocker traffic to hold real packets in traffic-manager queues. Test a release schedule based on a per-session clock or deadline rather than how much blocker traffic is present. “Class-independent” means READ, SELECT, and OPERATE should have similar release-time distributions after accounting for configured settings and information the attacker already sees. Measure queue occupancy and timing after subtracting the known delay step to see whether the queue still reveals the operation.',sty['BodyX']),
        p('<b>2. Make random choices hard to estimate from repeated samples.</b> The current 16-choice timing map contains a small set of configured delay steps. An attacker can learn those steps and estimate which one was used. Evaluate more finely spaced choices with fresh, independent random values for each transaction. This is only a candidate: repeated observations can still reveal the overall mixture of delays even when the exact random choice is hidden. Rerun pooled classifiers and check added latency and the fraction of baseline responses that fit within the target.',sty['BodyX']),
        p('<b>3. Address request cadence at the correct observation point.</b> A request gap is the time between two requests arriving from the master. A response-only delay cannot hide a gap already seen on the incoming link. If the threat model includes cadence, shape traffic before the attacker’s observation point, such as at the source or a trusted upstream boundary. If the attacker sees the master-to-switch link before that point, this switch’s response scheduler cannot remove the clue. Any shaping must preserve the SELECT→OPERATE sequence and be measured for added command latency.',sty['BodyX']),
        p('<b>4. Test against held-out attackers, not just one model.</b> After any change, rerun Random Forest, logistic regression, and support-vector machine tests using raw timing and timing after the known delay step is subtracted, both on single samples and groups of samples, with entirely new rounds. Report each operation’s recall, confusion matrices, confidence bounds, and tests that remove ACK, response time, request gap, and combinations of these clues. Require success at pool sizes 1, 5, and 20. Keep packet coverage and latency results beside classifier results.',sty['BodyX']),
        p('A design passes only if it reduces the adaptive attacker’s held-out capability without moving the cost into unacceptable latency or more late/unobfuscated replies. The current four measured policies do not yet achieve the classifier threshold.',sty['CalloutX']),
        PageBreak()]

    story += [p('13. Evidence boundaries and source files',sty['H1X']),
        p(f"The independent audit status is <b>{audit.get('status','not recorded')}</b>. The classifier training rounds are 0–39; held-out rounds are 40–99. The full acquisition contains {report['primary_exchanges']:,} primary exchanges. The four policies are paired within a 100-round randomized schedule. The independent audit reconstructs held-out predictions and checks them against the frozen scores and source data.",sty['BodyX']),
        p('Each policy was measured within the same randomized campaign, which makes the four D<sub>A</sub> settings comparable under this run’s workload and conditions. The first 40 rounds are used to fit and choose classifiers; the later 60 rounds test those choices on data not used for fitting. “Primary exchanges” are the recorded request/ACK/response transactions counted in the hardware capture. The independent audit confirms the result files agree with their source measurements and saved model predictions; it does not expand the experiment beyond this device and workload.',sty['BodyX']),
        p('What these data establish: measured master-facing latency distributions, baseline timing coverage estimates, tested classifier performance on held-out rounds, and the observed absence of missing primary responses, capture drops, and retransmission flags.',sty['BodyX']),
        p('What they do not establish: an exact switch-arrival time for every response; which protected transactions bypassed timing treatment; field-wide performance; cross-device fingerprinting; all possible attacker models; physical actuation outcomes; or zero probability of loss beyond the captured test. The tested attacker receives measured packet timing and can infer the selected D<sub>R</sub>; it is not separately given the switch’s exact per-packet D<sub>R</sub> value as an out-of-band feature. That stronger assumption would require a separate classifier run.',sty['BodyX']),
        p('Primary evidence: defense4/timing/latency_search/results/grid_random_screen_20260927T021133Z/. Adaptive-distribution diagnostics, all CSV summaries, PCA projections, classifier confusion matrices, provenance hashes, and the generation script are stored beside this PDF in adaptive_diagnostics/.',sty['SmallX']),
        p('Key terms',sty['H2X']),
        table([
            [p('Term',sty['GlossaryTermX']),p('Meaning',sty['GlossaryTermX'])],
            [p('D<sub>A</sub>',sty['GlossaryTermX']),p('Selected wait after the switch receives the outstation ACK; it sets the ACK release deadline. Tested centers: 5, 10, 15, and 20 ms, each with ±0.5 ms choices.',sty['GlossaryX'])],
            [p('D<sub>R</sub>',sty['GlossaryTermX']),p('Selected response-delay target after the ACK deadline. It is visible through the master-facing ACK-to-response CLRT. This run used a 1 ms center with ±0.5 ms choices.',sty['GlossaryX'])],
            [p('CLRT',sty['GlossaryTermX']),p('Time from acknowledgment to application response, measured at the master-facing link.',sty['GlossaryX'])],
            [p('Ingress / egress',sty['GlossaryTermX']),p('Ingress receives and processes a packet; egress sends it out of the switch.',sty['GlossaryX'])],
            [p('Traffic manager / queue',sty['GlossaryTermX']),p('The switch component schedules outgoing packets; a queue stores packets while they wait their turn.',sty['GlossaryX'])],
            [p('Timing OFF',sty['GlossaryTermX']),p('Paired baseline run with the timing defense disabled.',sty['GlossaryX'])],
            [p('Obfuscated',sty['GlossaryTermX']),p('Run with the timing defense enabled.',sty['GlossaryX'])],
            [p('Balanced accuracy',sty['GlossaryTermX']),p('Average of the percentage correctly recognized in each operation group; chance is 0.5 for two labels and 0.333 for three.',sty['GlossaryX'])],
            [p('Known delay choice',sty['GlossaryTermX']),p('A configured D_A or D_R timing choice. The attacker knows the possible values and can infer the selected value from observed timing.',sty['GlossaryX'])],
            [p('Subtracting known choices',sty['GlossaryTermX']),p('Removing the nearest expected D_A or D_R value from measured timing before classification.',sty['GlossaryX'])],
            [p('Pool size',sty['GlossaryTermX']),p('Number of same-operation samples summarized together for one attacker input.',sty['GlossaryX'])],
            [p('PRNG',sty['GlossaryTermX']),p('Pseudo-random number generator: program component that produces values used to choose timing settings.',sty['GlossaryX'])],
            [p('Held-out rounds',sty['GlossaryTermX']),p('Later test rounds kept separate from training, to check whether a model works on unseen samples.',sty['GlossaryX'])],
            [p('Confusion matrix',sty['GlossaryTermX']),p('A count of correct and mistaken operation labels, organized by true operation and predicted operation.',sty['GlossaryX'])],
            [p('PCA',sty['GlossaryTermX']),p('A way to project many measurements onto two plotted axes; useful for viewing patterns, not a classifier test.',sty['GlossaryX'])],
            [p('Baseline RTT past D<sub>A</sub>',sty['GlossaryTermX']),p('Request-to-response time in Timing OFF compared with the D_A center; a rough availability proxy, not a true deadline-miss count or packet loss.',sty['GlossaryX'])],
            [p('Late > selected CLRT + 1 ms',sty['GlossaryTermX']),p('Protected response exceeds its selected response timing target by more than 1 ms.',sty['GlossaryX'])],
        ],[1.65*inch,5.35*inch],font=7.2),
    ]
    doc=BaseDocTemplate(str(OUT/'seven_stage_timing_and_attacker_explainer.pdf'),pagesize=letter,
        leftMargin=.68*inch,rightMargin=.68*inch,topMargin=.62*inch,bottomMargin=.72*inch,
        title='What the Seven-Stage Timing Defense Does',author='Philip')
    frame=Frame(doc.leftMargin,doc.bottomMargin,doc.width,doc.height,id='normal')
    doc.addPageTemplates([PageTemplate(id='report',frames=frame,onPage=footer)])
    doc.build(story)
    print(f'Wrote {OUT/"seven_stage_timing_and_attacker_explainer.pdf"}')


if __name__=='__main__': build()
