#!/usr/bin/env python3
"""Auditable focused-run statistics and final-size publication figures."""
import argparse
import csv
import json
from pathlib import Path

import evaluate_focused as attacks
import figures as shared
import figures_random
from matplotlib.ticker import LogLocator, FuncFormatter

np=shared.np
plt=shared.plt
OPS=('READ','SELECT','OPERATE')
COLORS=('#0072B2','#D55E00','#009E73','#666666')


def distribution(values):
    values=np.asarray(values,dtype=float)
    if not len(values) or not np.isfinite(values).all():
        raise ValueError('Missing/nonfinite timing values')
    return dict(n=len(values),mean_ms=float(np.mean(values)),sd_ms=float(np.std(values,ddof=1)),
        variance_ms2=float(np.var(values,ddof=1)),**dict(zip(
            ('min_ms','p25_ms','median_ms','p75_ms','p95_ms','p99_ms','max_ms'),
            map(float,np.percentile(values,[0,25,50,75,95,99,100])))))


def metrics(rows):
    result={}
    for op in OPS:
        protected=[r for r in rows if r['arm']=='obfuscated' and r['txn_class']==op]
        native=[r for r in rows if r['arm']=='native' and r['txn_class']==op]
        stats={field:distribution([float(r[field]) for r in protected]) for field in (
            'ack_ms','clrt_ms','rt_ms','ack_minus_selected_ms','response_minus_selected_ms',
            'selected_da_ms','selected_gap_ms','selected_r_ms')}
        late=sum(float(r['response_minus_selected_ms'])>1. for r in protected)
        stats['late_over_1ms']=dict(count=late,total=len(protected),fraction=late/len(protected))
        stats['native_rt_ms']=distribution([float(r['rt_ms']) for r in native])
        stats['added_pooled_median_ms']=stats['rt_ms']['median_ms']-stats['native_rt_ms']['median_ms']
        differences=[]
        for rep in sorted({int(r['replicate']) for r in protected}):
            p=[float(r['rt_ms']) for r in protected if int(r['replicate'])==rep]
            n=[float(r['rt_ms']) for r in native if int(r['replicate'])==rep]
            if not n: raise ValueError('Missing matched baseline repetition')
            differences.append(float(np.median(p)-np.median(n)))
        stats['paired_block_median_difference_ms']=distribution(differences)
        result[op]=stats
    return result


def export(fig,out,stem):
    fig.savefig(out/(stem+'.pdf'))
    fig.savefig(out/(stem+'.png'),dpi=300)
    plt.close(fig)


def survival_values(values):
    values,counts=np.unique(np.asarray(values,dtype=float),return_counts=True)
    return values,(counts.sum()-np.r_[0,np.cumsum(counts)[:-1]])/counts.sum()


def plot_tails(rows,out):
    shared.set_style()
    fig,axes=plt.subplots(1,3,figsize=(7.16,2.65),sharey=True)
    plotted=[]
    all_values=[float(r['rt_ms']) for r in rows]
    for ax,op in zip(axes,OPS):
        for arm,color,dash,label in [('native','#666666','--','Timing OFF'),('obfuscated',COLORS[0],'-','Obfuscated')]:
            values,survival=survival_values([float(r['rt_ms']) for r in rows if r['arm']==arm and r['txn_class']==op])
            ax.step(values,survival,where='pre',color=color,linestyle=dash,label=label,linewidth=1)
            plotted.extend(dict(operation=op,arm=arm,rt_ms=float(x),fraction_at_or_above=float(y)) for x,y in zip(values,survival))
        ax.set_yscale('log');ax.set_xscale('log');ax.set_title(op)
        ax.set_xlim(min(all_values)/1.1,max(all_values)*1.1)
        ax.xaxis.set_major_locator(LogLocator(base=10,subs=(1,2,5)))
        ax.xaxis.set_major_formatter(FuncFormatter(lambda value,_:f'{value:g}'))
        ax.xaxis.set_minor_locator(LogLocator(base=10,subs=()))
        ax.set_xlabel('Response latency (ms)')
        ax.spines[['top','right']].set_visible(False)
        ax.grid(axis='y',color='.88',linewidth=.5)
    axes[0].set_ylabel('Fraction at or above latency')
    fig.legend(*axes[0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.5,1),ncol=2,frameon=False)
    fig.subplots_adjust(left=.09,right=.985,bottom=.24,top=.77,wspace=.25)
    export(fig,out,'focused_latency_tails')
    with (out/'focused_latency_tails.csv').open('w',newline='') as stream:
        w=csv.DictWriter(stream,fieldnames=list(plotted[0]));w.writeheader();w.writerows(plotted)


def plot_attacks(result,out):
    shared.set_style();fig,axes=plt.subplots(2,2,figsize=(7.16,4.4),sharex=True,sharey=True)
    plotted=[]
    scenarios=[('fixed_on_native','Fixed, Timing OFF','s',COLORS[3]),
               ('fixed_on_obfuscated','Fixed, Obfuscated','o',COLORS[0]),
               ('adaptive_on_obfuscated','Adaptive, Obfuscated','^',COLORS[1]),
               ('adaptive_on_offset_residuals','Adaptive, level-aware','D',COLORS[2])]
    for i,(task,title) in enumerate([('three_class','READ / SELECT / OPERATE'),('read_select','READ / SELECT')]):
        doc=result['tasks'][task]
        for j,(family,subtitle) in enumerate([('ack_response','ACK and CLRT features'),('all_timing','Including request spacing')]):
            ax=axes[i,j]
            for scenario,label,marker,color in scenarios:
                values=[]
                for pool in (1,5,20):
                    candidates=[r for r in doc['records'] if r['scenario']==scenario and r['pool']==pool and
                                (family=='all_timing' or r['feature'] in ('clrt','ack_clrt'))]
                    strongest=max(candidates,key=lambda r:r['mean_accuracy'])
                    values.append(strongest['mean_accuracy'])
                    plotted.append(dict(task=task,family=family,scenario=scenario,pool=pool,
                        balanced_accuracy=strongest['mean_accuracy'],model=strongest['model'],feature=strongest['feature']))
                ax.plot(range(3),values,color=color,marker=marker,markersize=4,linewidth=1,label=label)
            ax.axhline(doc['chance'],color='.4',linestyle=':',linewidth=.8)
            ax.set_title(title+'\n'+subtitle,fontsize=8.5)
            ax.set_ylim(0,1.04);ax.set_xticks(range(3),['1','5','20'])
            if i==1: ax.set_xlabel('Exchanges per signature')
            if j==0: ax.set_ylabel('Balanced accuracy')
            ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',color='.88',linewidth=.5)
    fig.legend(*axes[0,0].get_legend_handles_labels(),loc='upper center',bbox_to_anchor=(.5,1),ncol=2,frameon=False)
    fig.subplots_adjust(left=.08,right=.985,bottom=.12,top=.78,hspace=.6,wspace=.18)
    export(fig,out,'focused_attack_accuracy')
    with (out/'focused_attack_accuracy.csv').open('w',newline='') as stream:
        w=csv.DictWriter(stream,fieldnames=list(plotted[0]));w.writeheader();w.writerows(plotted)


def generate(results,protocol_path):
    rows,protocol,levels=attacks.load(results/'measurements.json',results/'primarytransactions.csv',protocol_path,True)
    doc=json.loads((results/'measurements.json').read_text())
    audit=json.loads((results/'tcp_audit.json').read_text())
    if audit['measurements_sha256']!=attacks.sha(results/'measurements.json'):
        raise ValueError('TCP audit belongs to different measurements')
    attack=json.loads((results/'attacks_heldout.json').read_text())
    if not attack['complete_attack_coverage'] or attack['protocol']!=protocol or attack['test_sha256']!=attacks.digest(attacks.split_rows(rows,protocol,'test')):
        raise ValueError('Held-out classifier results differ from current evidence')
    full=metrics(rows);heldout=metrics(attacks.split_rows(rows,protocol,'test'))
    report=dict(protocol=protocol,all_repetitions=full,heldout_repetitions=heldout,
        primary_exchanges=len(rows),successful_primary_exchanges=len(rows),
        missing_primary_responses=0,qualification='All scheduled exchanges passed strict capture/protocol validation; absence of capture loss is not proof of zero network loss.',
        capture_packets=sum(b['capture']['received_packets'] for b in doc['blocks'].values()),
        capture_drops=sum(b['capture']['dropped_packets'] for b in doc['blocks'].values()),
        retransmission_flagged_frames=audit['flagged_frame_count'],
        timing_miss_definition='Observed request-to-response latency exceeds selected response target by more than 1 ms; not a transaction failure',
        strongest_attack_bounds={k:v['envelopes'] for k,v in attack['tasks'].items()},
        meets_full_criterion=attack['meets_full_criterion'])
    attacks.base.save(results/'focused_statistics.json',report)
    out=results/'figures';out.mkdir(exist_ok=True)
    figures_random.generate(results/'measurements.json',results/'primarytransactions.csv',protocol['policy_name'],out/'timing_realization')
    plot_tails(rows,out);plot_attacks(attack,out)
    provenance=dict(inputs_and_code={str(p.resolve()):attacks.sha(p) for p in (
        results/'measurements.json',results/'primarytransactions.csv',results/'tcp_audit.json',
        results/'attacks_heldout.json',protocol_path,Path(__file__),Path(shared.__file__),Path(figures_random.__file__))},
        captions={
            'focused_latency_tails':'Empirical upper-tail distributions of request-to-response latency. All 100 paired repetitions; logarithmic axes; full observed tails retained.',
            'focused_attack_accuracy':'Held-out balanced accuracy, repetitions 40–99. Each point is the strongest tested model/feature combination for that scenario and pool size. The level-aware variant uses ACK/CLRT residuals in both columns. Dotted lines show chance. Simultaneous uncertainty bounds are reported in focused_statistics.json; points do not imply a confidence guarantee.'})
    attacks.base.save(out/'focused.provenance.json',provenance)
    (out/'FIGURES.sha256').write_text(''.join(attacks.sha(p)+'  '+str(p.relative_to(out))+'\n' for p in sorted(out.rglob('*')) if p.is_file() and p.name!='FIGURES.sha256'))
    lines=['# Focused hardware results','',f"Validated primary exchanges: {len(rows):,}.",
        f"Capture drops: {report['capture_drops']}; TCP retransmission flags: {report['retransmission_flagged_frames']}.",'',
        '| Operation | Median total (ms) | p99 total (ms) | Added pooled median (ms) | >1 ms late |',
        '|---|---:|---:|---:|---:|']
    for op,s in full.items():
        lines.append(f"| {op} | {s['rt_ms']['median_ms']:.3f} | {s['rt_ms']['p99_ms']:.3f} | {s['added_pooled_median_ms']:.3f} | {s['late_over_1ms']['fraction']:.2%} |")
    lines+=['','Full tested attacker criterion met: '+str(report['meets_full_criterion'])+'.',
        'This is a measured result for the tested classifiers and transaction classes on one SEL-751, not a guarantee against all attackers.']
    (results/'RESULTS.md').write_text('\n'.join(lines)+'\n')
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--results',type=Path,required=True);p.add_argument('--protocol',type=Path,required=True)
    a=p.parse_args();generate(a.results,a.protocol)
