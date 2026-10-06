#!/usr/bin/env python3
"""Coverage estimates, variance, latency and classifier tradeoffs for the DA grid."""
import argparse
import csv
import json
from pathlib import Path

import grid_analysis as analysis
import focused_report as focused
import figures_random

np=focused.np
plt=focused.plt
OPS=focused.OPS


def coverage(rows,plan):
    """Joint availability proxy on Timing OFF; never labels protected arrivals."""
    native=[r for r in rows if r['arm']=='native']
    result={}
    for op in OPS:
        rr=[r for r in native if r['txn_class']==op]
        if not rr:raise ValueError('Missing Timing OFF operation')
        ack=np.asarray([float(r['ack_ms']) for r in rr]);rt=np.asarray([float(r['rt_ms']) for r in rr])
        if not np.isfinite(ack).all() or not np.isfinite(rt).all():raise ValueError('Invalid coverage timing')
        response=np.zeros(len(rr));joint=np.zeros(len(rr));weight_sum=0.
        for entry in plan['entries']:
            weight=(entry['high']-entry['low']+1)/256.
            da=entry['d_ticks']/1e6;deadline=entry['da_dr_ticks']/1e6
            response+=weight*(rt<=deadline)
            joint+=weight*((ack<=da)&(rt<=deadline));weight_sum+=weight
        if abs(weight_sum-1)>1e-12:raise ValueError('Random selection weights do not sum to one')
        rounds={str(rep):float(np.mean(joint[[int(r['replicate'])==rep for r in rr]]))
                for rep in sorted({int(r['replicate']) for r in rr})}
        center=float(plan['center_da_ms'])
        result[op]=dict(native_n=len(rr),beyond_da_center_count=int(np.sum(rt>center)),
            beyond_da_center_fraction=float(np.mean(rt>center)),
            estimated_response_availability=float(response.mean()),
            estimated_joint_ack_response_availability=float(joint.mean()),
            estimated_joint_unavailability=float(1-joint.mean()),by_round_joint_availability=rounds)
    return result


def timing(rows):
    result=focused.metrics(rows)
    for op in OPS:
        native=[r for r in rows if r['arm']=='native' and r['txn_class']==op]
        for field in ('ack_ms','clrt_ms'):
            result[op]['native_'+field]=focused.distribution([float(r[field]) for r in native])
        result[op]['clrt_variance_ratio']=result[op]['clrt_ms']['variance_ms2']/result[op]['native_clrt_ms']['variance_ms2']
    return result


def write_csv(path,rows):
    with path.open('w',newline='') as f:
        writer=csv.DictWriter(f,fieldnames=list(rows[0]));writer.writeheader();writer.writerows(rows)


def plot_mechanism(report,out):
    focused.shared.set_style()
    fig,axes=plt.subplots(1,3,figsize=(7.16,2.7))
    rows=[];names=report['protocol']['policy_names'];delays=report['protocol']['delays_ms']
    for op,color,dash in zip(OPS,focused.COLORS,('-','--',':')):
        values=[]
        for name in names:
            p=report['policies'][name];stats=p['timing'][op]
            values.append([100*p['coverage'][op]['estimated_joint_ack_response_availability'],
                           stats['clrt_ms']['variance_ms2'],stats['added_pooled_median_ms']])
            rows.append(dict(policy=name,operation=op,da_ms=p['center_da_ms'],
                estimated_joint_coverage_percent=values[-1][0],clrt_variance_ms2=values[-1][1],
                added_median_ms=values[-1][2],clrt_sd_ms=stats['clrt_ms']['sd_ms'],
                native_clrt_variance_ms2=stats['native_clrt_ms']['variance_ms2']))
        for i,ax in enumerate(axes):
            ax.plot(delays,[v[i] for v in values],marker='o',markersize=3,color=color,linestyle=dash,linewidth=1,label=op)
    labels=['Estimated joint coverage (%)','CLRT variance (ms²)','Added median latency (ms)']
    for ax,label in zip(axes,labels):
        ax.set_xlabel('Configured $D_A$ center (ms)');ax.set_ylabel(label)
        ax.set_xticks(delays);ax.spines[['top','right']].set_visible(False)
        ax.grid(axis='y',color='.88',linewidth=.5)
    axes[0].set_ylim(0,101);axes[1].set_yscale('log')
    fig.subplots_adjust(left=.08,right=.985,bottom=.21,top=.94,wspace=.48)
    focused.export(fig,out,'grid_coverage_variance_latency')
    write_csv(out/'grid_coverage_variance_latency.csv',rows)


def plot_attacks(report,bounds,out,stem):
    focused.shared.set_style();fig,axes=plt.subplots(1,2,figsize=(7.16,2.9),sharey=True)
    rows=[]
    for ax,task,title in zip(axes,('three_class','read_select'),('READ / SELECT / OPERATE','READ / SELECT')):
        doc=bounds[task];ticks=[];labels=[]
        for name in report['protocol']['policy_names']:
            x=report['latencies'][name]['worst_added_median_ms'];r=doc['per_policy'][name]
            ax.errorbar(x,r['max_accuracy'],yerr=[[0.],[max(0.,r['upper_bound']-r['max_accuracy'])]],
                fmt='o',markersize=4,color='#0072B2',capsize=3,elinewidth=1)
            ticks.append(x);labels.append(f"{x:.1f}\n($D_A$={report['latencies'][name]['center_da_ms']:g})")
            rows.append(dict(task=task,policy=name,added_median_ms=x,max_accuracy=r['max_accuracy'],upper_bound=r['upper_bound'],passes=r['passes']))
        ax.axhline(doc['chance'],color='.4',linestyle=':',linewidth=.8)
        ax.axhline(doc['threshold'],color='.4',linestyle='--',linewidth=.8)
        xmax=max(ticks)
        ax.set_xlim(min(ticks)-.7,xmax+4.0)
        ax.text(xmax+3.8,doc['chance'],'chance',ha='right',va='bottom',fontsize=6.2,color='.35')
        ax.text(xmax+3.8,doc['threshold'],'criterion',ha='right',va='bottom',fontsize=6.2,color='.35')
        ax.set_xticks(ticks,labels);ax.set_xlabel('Added median latency (ms)');ax.set_title(title)
        ax.set_ylim(0,1.04);ax.spines[['top','right']].set_visible(False);ax.grid(axis='y',color='.88',linewidth=.5)
    axes[0].set_ylabel('Balanced accuracy')
    fig.subplots_adjust(left=.08,right=.985,bottom=.26,top=.87,wspace=.2)
    focused.export(fig,out,stem);write_csv(out/(stem+'.csv'),rows)


def generate(run,results):
    final=results/'final';measurement=final/'measurements.json';transactions=final/'primarytransactions.csv'
    protocol,subsets=analysis.load(run,measurement,transactions,True)
    attackers=json.loads((results/'grid_attacks.json').read_text())
    if attackers['measurements_sha256']!=analysis.core.sha(measurement) or attackers['transactions_sha256']!=analysis.core.sha(transactions):
        raise ValueError('Classifier results differ from measurement inputs')
    if attackers['protocol']!=protocol or not attackers['complete_attack_coverage']:raise ValueError('Incomplete grid attacker coverage')
    for name,h in attackers['policy_results_sha256'].items():
        if analysis.core.sha(results/name/'final/attacks_heldout.json')!=h:raise ValueError('Changed policy result')
    audit=json.loads((final/'tcp_audit.json').read_text());doc=json.loads(measurement.read_text())
    if audit['measurements_sha256']!=analysis.core.sha(measurement):raise ValueError('Mismatched capture audit')
    report=dict(protocol=protocol,policies={},latencies={},
        primary_exchanges=doc['row_count'],missing_primary_responses=0,
        capture_drops=sum(b['capture']['dropped_packets'] for b in doc['blocks'].values()),
        retransmission_flagged_frames=audit['flagged_frame_count'],
        coverage_interpretation='Availability estimated from Timing OFF master-facing captures, not measured switch arrival. This proxy omits effects of protected-path command holds and queue state. It cannot label protected transactions as unmodified or unobfuscated.',
        variance_interpretation='All valid samples retained, including long tails. Changes in variance and accuracy are associations, not causal attribution to deadline misses.')
    for name,(rows,p,levels) in subsets.items():
        plan=json.loads((run/'plans'/(name+'.json')).read_text());stats=timing(rows)
        report['policies'][name]=dict(center_da_ms=plan['center_da_ms'],timing=stats,coverage=coverage(rows,plan),
            heldout_timing=timing(analysis.core.split_rows(rows,p,'test')),
            heldout_coverage=coverage(analysis.core.split_rows(rows,p,'test'),plan))
        report['latencies'][name]=dict(center_da_ms=plan['center_da_ms'],
            worst_added_median_ms=max(s['added_pooled_median_ms'] for s in stats.values()),
            worst_total_median_ms=max(s['rt_ms']['median_ms'] for s in stats.values()),
            worst_p99_ms=max(s['rt_ms']['p99_ms'] for s in stats.values()))
    report['selection']=analysis.rank_policies(attackers['primary_ack_clrt'],report['latencies'])
    analysis.campaign.rc.write_json(results/'grid_report.json',report)
    out=results/'figures';out.mkdir(parents=True,exist_ok=True)
    plot_mechanism(report,out)
    plot_attacks(report,attackers['primary_ack_clrt'],out,'grid_ack_clrt_tradeoff')
    plot_attacks(report,attackers['all_timing_diagnostic'],out,'grid_all_timing_diagnostic')
    for name in protocol['policy_names']:
        figures_random.generate(measurement,transactions,name,out/name)
    provenance=dict(inputs_and_code={str(p.resolve()):analysis.core.sha(p) for p in (
        measurement,transactions,results/'grid_attacks.json',final/'tcp_audit.json',run/'protocol.json',
        Path(__file__),Path(analysis.__file__),Path(focused.__file__),Path(figures_random.__file__),Path(focused.shared.__file__))},
        captions={
            'grid_coverage_variance_latency':'All 100 paired rounds per delay. Coverage is the Timing OFF proxy for joint ACK/response availability, averaged over the 16 configured selections. CLRT variance uses every protected sample and a log axis. Added median latency is the difference between each operation’s protected and paired Timing OFF medians.',
            'grid_ack_clrt_tradeoff':'Held-out rounds 40–99. Points are the strongest fixed/adaptive/level-aware ACK/CLRT attack across tested models and pools; bars extend to approximate simultaneous upper bounds across four policies and attacks. X values are the largest added median over the three operations.',
            'grid_all_timing_diagnostic':'Same comparison including request spacing. This diagnostic is reported separately and does not determine ACK/CLRT policy selection.'})
    analysis.campaign.rc.write_json(out/'grid.provenance.json',provenance)
    (out/'FIGURES.sha256').write_text(''.join(analysis.core.sha(p)+'  '+str(p.relative_to(out))+'\n' for p in sorted(out.rglob('*')) if p.is_file() and p.name!='FIGURES.sha256'))
    return report


if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--run',type=Path,required=True);p.add_argument('--results',type=Path,required=True)
    a=p.parse_args();generate(a.run,a.results)
