"""Six figure families rendered exclusively from exported, exact CSV tables."""
import csv
import json
from pathlib import Path

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import numpy as np

ARMS=('off','timing_only','size_only','combined')
COLORS=('#0072B2','#E69F00','#009E73','#CC79A7')
STYLES=('-','--','-.',':')


def read(path):
    with open(path,newline='') as handle:
        return list(csv.DictReader(handle))


def number(row,key):
    return None if row.get(key) in ('',None) else float(row[key])


def finish(fig,path,source):
    fig.text(.01,.002,'Exact source: '+source,fontsize=7)
    fig.tight_layout(rect=(0,.02,1,.98))
    fig.savefig(path,metadata={'CreationDate':None,'ModDate':None})
    plt.close(fig)


def unavailable(axis,label='No observed support'):
    axis.text(.5,.5,label,ha='center',va='center',transform=axis.transAxes,fontsize=8)


def render(directory):
    root=Path(directory)
    output=root/'figures'
    output.mkdir()
    distributions=read(root/'distributions.csv')
    conditions=sorted({r['condition_id'] for r in distributions})
    fig,axes=plt.subplots(max(1,len(conditions)),2,figsize=(10,max(3,len(conditions)*2.1)),squeeze=False)
    for i,condition in enumerate(conditions):
        for j,metric in enumerate(('clrt_ms','resp_len')):
            axis=axes[i,j]
            for arm,color,style in zip(ARMS,COLORS,STYLES):
                values=[r for r in distributions if r['condition_id']==condition and r['metric']==metric and r['arm']==arm]
                if values and number(values[0],'n'):
                    axis.step([number(r,'right') for r in values],
                        [number(r,'cumulative')/number(r,'n') for r in values],where='post',
                        label=arm,color=color,linestyle=style)
            axis.set(title=condition,xlabel='CLRT (ms)' if j==0 else 'Observed response TCP payload (bytes)',ylabel='Cumulative fraction',ylim=(0,1.02))
            if i==0 and j==1:
                axis.legend(fontsize=7)
    finish(fig,output/'four_arm_timing_size.pdf','distributions.csv; shared full-tail edges per condition/metric')

    residuals=read(root/'precision_residuals.csv')
    fig,axes=plt.subplots(max(1,len(conditions)),3,figsize=(12,max(3,len(conditions)*2.1)),squeeze=False)
    for i,condition in enumerate(conditions):
        for j,operation in enumerate(('READ','SELECT','OPERATE')):
            axis=axes[i,j]
            present=False
            for arm,color,style in zip(ARMS,COLORS,STYLES):
                subset=[r for r in residuals if r['condition_id']==condition and r['operation']==operation and r['arm']==arm]
                values=sorted(number(r,'abs_error_ms') for r in subset)
                if values:
                    present=True
                    axis.step(values,np.arange(1,len(values)+1)/len(values),where='post',label=arm,color=color,linestyle=style)
            if not present:
                unavailable(axis)
            axis.axvline(.1,color='.5',linewidth=.6)
            axis.set(title=condition+' / '+operation,xlabel='|CLRT − D| (ms), complete tail',ylabel='Cumulative fraction',ylim=(0,1.02))
            if i==0 and j==2:
                axis.legend(fontsize=7)
    finish(fig,output/'precision_full_tails.pdf','precision_residuals.csv; 100µs criterion applies to timing arms')

    windows=read(root/'oracle_windows.csv')
    fig,axes=plt.subplots(1,2,figsize=(10,4))
    for axis,metric,label in zip(axes,('mean_ms','variance_ms2'),('Window mean CLRT (ms)','Window sample variance (ms²)')):
        present=False
        for arm,color in zip(ARMS,COLORS):
            subset=[r for r in windows if r['arm']==arm and r['split']=='testing']
            if subset:
                present=True
                axis.scatter([number(r,'k') for r in subset],[number(r,metric) for r in subset],s=7,alpha=.4,color=color,label=arm)
        if not present:
            unavailable(axis)
        axis.set(xlabel='K observations (nonoverlapping)',ylabel=label,xticks=[8,32,64])
    if windows:
        axes[1].legend(fontsize=7)
    fig.suptitle('Oracle-assisted operation-grouped windows; no device-class claim')
    finish(fig,output/'oracle_window_mean_variance.pdf','oracle_windows.csv')

    attacks=read(root/'attack_summary.csv')
    fig,axes=plt.subplots(2,4,figsize=(15,7),sharey=True)
    for i,attacker in enumerate(('fixed','adaptive')):
        for j,feature in enumerate(('clrt','ack_clrt','size','joint')):
            axis=axes[i,j]
            any_support=False
            for arm,color,style in zip(ARMS,COLORS,STYLES):
                subset=[r for r in attacks if r['attacker']==attacker and r['feature']==feature and r['arm']==arm and number(r,'balanced_accuracy') is not None]
                lookup={r['condition_id']:number(r,'balanced_accuracy') for r in subset}
                if lookup:
                    any_support=True
                    axis.plot([x for x,c in enumerate(conditions) if c in lookup],[lookup[c] for c in conditions if c in lookup],color=color,linestyle=style,marker='o',markersize=3,label=arm)
            if not any_support:
                unavailable(axis)
            axis.axhline(1/3,color='.5',linewidth=.6)
            axis.set(title=attacker+' / '+feature,ylim=(0,1.03),xticks=range(len(conditions)),xticklabels=conditions)
            axis.tick_params(axis='x',labelrotation=90,labelsize=7)
            if j==0:
                axis.set_ylabel('Balanced accuracy')
    axes[0,-1].legend(fontsize=7)
    finish(fig,output/'fixed_adaptive_four_features.pdf','attack_summary.csv')

    reductions=read(root/'paired_reductions.csv')
    fig,axes=plt.subplots(1,2,figsize=(10,4),sharey=True)
    condition_map={'D05_J2p4':(5,2.4),'D10_J2p4':(10,2.4),'D15_J2p4':(15,2.4),'D20_J2p4':(20,2.4),
                   'D10_J5':(10,5),'D10_J10':(10,10),'D10_J15':(10,15),'D10_J20':(10,20)}
    for axis,dimension in zip(axes,(0,1)):
        subset=[r for r in reductions if r['feature']=='joint' and r['attacker']=='fixed' and r['arm']=='combined'
                and r['metric']=='balanced_accuracy' and number(r,'estimate') is not None
                and (condition_map[r['condition_id']][1]==2.4 if dimension==0 else condition_map[r['condition_id']][0]==10)]
        subset.sort(key=lambda r:condition_map[r['condition_id']][dimension])
        if subset:
            y=np.array([number(r,'estimate') for r in subset])
            low=np.array([number(r,'lower') for r in subset]);high=np.array([number(r,'upper') for r in subset])
            axis.errorbar([condition_map[r['condition_id']][dimension] for r in subset],y,
                          yerr=np.asarray([np.maximum(0,y-low),np.maximum(0,high-y)]),marker='o',capsize=3,color=COLORS[0])
        else:
            unavailable(axis,'No complete paired-round interval')
        axis.axhline(0,color='.5',linewidth=.6)
        axis.set(xlabel='D (ms), J=2.4ms' if dimension==0 else 'J (ms), D=10ms',ylabel='Native − combined balanced accuracy')
    finish(fig,output/'separate_D_J_curves.pdf','paired_reductions.csv; conditional95% paired-round intervals')

    fig,axes=plt.subplots(1,3,figsize=(12,4))
    nb=[r for r in attacks if r['feature']=='nb']
    for arm,color,style in zip(ARMS,COLORS,STYLES):
        subset=[r for r in nb if r['arm']==arm and r['attacker']=='fixed' and number(r,'balanced_accuracy') is not None]
        axes[0].scatter([number(r,'k') for r in subset],[number(r,'balanced_accuracy') for r in subset],label=arm,color=color,s=18)
        ws=[r for r in windows if r['arm']==arm and r['split']=='testing']
        axes[1].scatter([number(r,'k') for r in ws],[number(r,'elapsed_ms') for r in ws],color=color,s=7,alpha=.3)
        axes[2].scatter([number(r,'k') for r in subset],[number(r,'n') for r in subset],color=color,s=18)
    for axis,label in zip(axes,('NB fixed balanced accuracy','Elapsed duration (ms)','Held-out window support')):
        axis.set(xlabel='K observations',ylabel=label,xticks=[8,32,64])
        if not nb:
            unavailable(axis)
    axes[0].set_ylim(0,1.03)
    axes[0].legend(fontsize=7)
    finish(fig,output/'NB_K_duration_support.pdf','attack_summary.csv, oracle_windows.csv; oracle-assisted windows')

    costs=read(root/'costs.csv')
    utility=read(root/'counter_utility.csv')
    metrics=('rt_ms','internal_bytes','timestamp_precision_ns','loss','fallback','realized_j_ms','correct')
    fig,axes=plt.subplots(2,4,figsize=(14,7))
    privacy={(r['condition_id'],r['arm']):number(r,'balanced_accuracy') for r in attacks
             if r['feature']=='joint' and r['attacker']=='fixed'}
    for axis,metric in zip(axes.flat,metrics):
        present=False
        for arm,color in zip(ARMS,COLORS):
            subset=[r for r in costs if r['arm']==arm and r['operation']=='all' and r['metric']==metric and number(r,'mean') is not None
                    and privacy.get((r['condition_id'],arm)) is not None]
            if subset:
                present=True
                axis.scatter([number(r,'mean') for r in subset],[privacy[r['condition_id'],arm] for r in subset],label=arm,color=color,s=25)
            if metric=='fallback' and not subset:
                aggregate=[r for r in utility if r.get('arm')==arm and r.get('split')=='testing'
                    and number(r,'outcome_OUT_ACK_FALLBACK') is not None and number(r,'outcome_OUT_RESP_FALLBACK') is not None
                    and privacy.get((r.get('condition_id'),arm)) is not None]
                if aggregate:
                    present=True
                    axis.scatter([number(r,'outcome_OUT_ACK_FALLBACK')+number(r,'outcome_OUT_RESP_FALLBACK') for r in aggregate],
                        [privacy[r['condition_id'],arm] for r in aggregate],label=arm,color=color,s=25)
        if not present:
            unavailable(axis,'Cost metric unavailable')
        axis.set(xlabel=metric+' (observed mean)',ylabel='Fixed joint balanced accuracy',ylim=(0,1.03))
        if metric=='fallback' and present:
            axis.set_xlabel('Recorded ACK+RESP fallback count per trial')
    axes.flat[-1].axis('off')
    handles,labels=axes.flat[0].get_legend_handles_labels()
    axes.flat[-1].legend(handles,labels,loc='center',fontsize=8)
    finish(fig,output/'privacy_cost.pdf','costs.csv, attack_summary.csv, counter_utility.csv; trial fallback counts stay aggregate')
    (output/'sources.json').write_text(json.dumps({
        'four_arm_timing_size.pdf':['distributions.csv'],
        'precision_full_tails.pdf':['precision_residuals.csv','precision_summary.csv'],
        'oracle_window_mean_variance.pdf':['oracle_windows.csv'],
        'fixed_adaptive_four_features.pdf':['attack_summary.csv'],
        'separate_D_J_curves.pdf':['paired_reductions.csv'],
        'NB_K_duration_support.pdf':['attack_summary.csv','oracle_windows.csv'],
        'privacy_cost.pdf':['costs.csv','attack_summary.csv','counter_utility.csv']},indent=2)+'\n')
