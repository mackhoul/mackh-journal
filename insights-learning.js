/* Pure learning/risk calculations. No storage, network or DOM. */
(function(root,factory){ const api=factory(); if(typeof module==='object'&&module.exports) module.exports=api; else root.MJLearning=api; })(typeof globalThis==='object'?globalThis:this,function(){
  'use strict';
  const num=v=>v===''||v===null||v===undefined?NaN:Number(v);
  const money=n=>(n>0?'+':n<0?'−':'')+'$'+Math.abs(n).toFixed(2);
  // «1 запись», «3 записи», «5 записей»
  const ruRecords=n=>{const a=n%10,c=n%100;return n+' '+(a===1&&c!==11?'запись':a>=2&&a<=4&&(c<12||c>14)?'записи':'записей');};
  function day(instant,timezone){
    const parts=new Intl.DateTimeFormat('en-CA',{timeZone:timezone,year:'numeric',month:'2-digit',day:'2-digit'}).formatToParts(new Date(instant));
    const get=k=>parts.find(p=>p.type===k).value;
    return get('year')+'-'+get('month')+'-'+get('day');
  }
  function ruleAt(history,date){
    return (history||[]).filter(h=>h&&/^\d{4}-\d{2}-\d{2}$/.test(h.effectiveDay)&&h.effectiveDay<=date)
      .map((h,i)=>({h,i})).sort((a,b)=>a.h.effectiveDay.localeCompare(b.h.effectiveDay)||String(a.h.savedAt||'').localeCompare(String(b.h.savedAt||''))||a.i-b.i).at(-1)?.h||null;
  }
  function modelR(t){
    if(t.result==='loss') return -1; if(t.result==='be') return 0;
    if(t.result!=='win') return null;
    return parseRR(t.rr);
  }
  function parseRR(value){
    const raw=String(value??'').trim().replace(',','.');
    const m=/^(\d+(?:\.\d+)?|\.\d+)\s*[:/]\s*(\d+(?:\.\d+)?|\.\d+)$/.exec(raw);
    const n=m?Number(m[2])/Number(m[1]):/^(\d+(?:\.\d+)?|\.\d+)$/.test(raw)?Number(raw):NaN;
    return Number.isFinite(n)&&n>0?n:null;
  }
  function position(o){
    const cap=num(o.capital),pct=num(o.riskPct),max=num(o.maxPct),e=num(o.entry),s=num(o.stop);
    const multiplier=o.multiplier===undefined?1:num(o.multiplier),feeIn=o.feeEntry===undefined?0:num(o.feeEntry),feeOut=o.feeExit===undefined?0:num(o.feeExit);
    const step=o.step===undefined?.0001:num(o.step),minimum=o.minimum===undefined?step:num(o.minimum);
    const fail=reason=>({size:null,risk:null,budget:null,reason});
    if(!Number.isFinite(cap)||cap<=0||!Number.isFinite(pct)||pct<=0||pct>100) return fail('budget');
    if(Number.isFinite(max)&&(max<=0||max>100||pct>max)) return fail('maximum');
    if(!Number.isFinite(e)||!Number.isFinite(s)||e<=0||s<=0||!['buy','sell'].includes(o.dir)||!(o.dir==='buy'?s<e:s>e)) return fail('stop');
    if(![multiplier,step,minimum].every(x=>Number.isFinite(x)&&x>0)||![feeIn,feeOut].every(x=>Number.isFinite(x)&&x>=0)) return fail('contract');
    const unit=(Math.abs(e-s)+e*feeIn+s*feeOut)*multiplier,budget=cap*pct/100;
    let size=Math.floor(budget/unit/step+1e-10)*step;
    // Floating point tolerance must never round a full increment above the budget.
    if(size*unit>budget+1e-8) size-=step;
    size=Number(size.toPrecision(12));
    if(size<minimum||size<=0) return fail('minimum');
    return {size,risk:size*unit,budget,unit,reason:null};
  }
  function realisedR(t){const s=t.riskSnapshot; const pnl=num(t.netPnl);return s?.confirmed===true&&num(s.riskUsd)>0&&Number.isFinite(pnl)?pnl/num(s.riskUsd):null;}
  const context=(t,c)=>(t.strategyId||'')===(c.strategyId||'')&&(t.strategyRevId||'')===(c.strategyRevId||'');
  const order=(a,b)=>String(a.date||'').localeCompare(String(b.date||''))||String(a.id).localeCompare(String(b.id),undefined,{numeric:true});
  function cards(list,{prefs={},lang='ru',net=x=>num(x.pnl)}={}){
    const ru=lang==='ru',L=(a,b)=>ru?a:b,out=[];
    const add=(id,type,text,meta,rec,act,rows)=>out.push({id,type,text,meta,rec,act,tradeIds:rows.map(x=>x.id),dismissCount:rows.length});
    const tracking=prefs.tracking;
    if(tracking?.key&&tracking.id){
      const all=list.filter(t=>context(t,tracking)&&t.date>=tracking.sinceDay).sort(order);
      const assessed=all.filter(t=>t.learning?.trackingId===tracking.id&&t.learning.errorKey===tracking.key&&typeof t.learning.errorPresent==='boolean');
      if(assessed.length>=40){
        const prev=assessed.slice(-40,-20),cur=assessed.slice(-20),p=prev.filter(t=>t.learning.errorPresent).length,c=cur.filter(t=>t.learning.errorPresent).length,d=(c-p)*5;
        const start=all.indexOf(prev[0]),end=all.indexOf(cur.at(-1)),unknown=all.slice(start,end+1).filter(t=>!assessed.includes(t)).length;
        add('mistake_dynamics','info',L(`Выбранная ошибка «${tracking.labelRu||tracking.key}»: ${c} из 20, раньше ${p} из 20; ${d>0?'+':d<0?'−':''}${Math.abs(d)} п.п.`,`Selected mistake "${tracking.labelEn||tracking.key}": ${c} of 20, previously ${p} of 20; ${d>0?'+':d<0?'−':''}${Math.abs(d)} pp`),
          L(`Без оценки этой ошибки в периоде: ${unknown}. Два окна по 20 явных ответов в одной редакции стратегии`,`Not assessed for this mistake within the period: ${unknown}. Two windows of 20 explicit answers in one strategy revision`),
          L('Это частота ваших отметок, не доказательство устранения причины. При одинаковой дате используется стабильный порядок id, не время входа','This is the frequency of your own marks, not proof that the cause is resolved. Same-date records use stable ID order, not entry time'),
          L('Разберите оставшиеся случаи и уточните одно условие проверки перед входом','Review the remaining cases and refine one condition to check before entry'),cur.filter(t=>t.learning.errorPresent));
      }else if(assessed.length){
        add('mistake_dynamics','info',L(`Выбранная ошибка: ${assessed.length} из 40 оценок для сравнения`,`Selected mistake: ${assessed.length} of 40 assessments for a comparison`),L(`Без оценки: ${all.length-assessed.length}`,`Not assessed: ${all.length-assessed.length}`),L('Пока нельзя сделать вывод об изменении частоты','There is not enough information to describe a change in frequency'),L('Отмечайте «была / не было» только если можете подтвердить ответ','Mark present or absent only when you can confirm the answer'),all.filter(t=>!assessed.includes(t)));
      }
    }
    // Limits apply to the whole account, including quick entries, not just the analytics subset.
    const days=[...new Set(list.map(t=>t.date).filter(x=>/^\d{4}-\d{2}-\d{2}$/.test(x)))].sort();
    const exceeded=[],lossDays=[];
    for(const date of days){
      const rows=list.filter(t=>t.date===date),rule=ruleAt(prefs.history,date); if(!rule) continue;
      // A rule entered during a day must not retrospectively accuse existing date-only records.
      // At least one new entry must explicitly carry this rule's snapshot before that day is reviewed.
      if(rule.savedAt&&day(rule.savedAt,rule.timezone||'UTC')>=date&&!rows.some(t=>t.dayPolicy?.ruleSavedAt===rule.savedAt))continue;
      if(Number.isInteger(rule.maxTrades)&&rule.maxTrades>0&&rows.length>rule.maxTrades) exceeded.push({date,rows,rule});
      const vals=rows.map(net),known=vals.filter(Number.isFinite),pnl=known.reduce((s,v)=>s+v,0);
      if(num(rule.dailyLoss)>0&&pnl<=-num(rule.dailyLoss)) lossDays.push({date,rows,rule,pnl,unknown:vals.length-known.length});
    }
    if(exceeded.length){const x=exceeded.at(-1);add('trade_limit_'+x.date,'warn',L(`${x.date}: ${ruRecords(x.rows.length)} при личном лимите ${x.rule.maxTrades}`,`${x.date}: ${x.rows.length} records against your limit of ${x.rule.maxTrades}`),L(`Сверх лимита ${x.rows.length-x.rule.maxTrades}; день аккаунта — ${x.rule.timezone}`,`${x.rows.length-x.rule.maxTrades} over the limit; account day — ${x.rule.timezone}`),L('Считаются отдельные записи, включая быстрые. Частичные исполнения могут быть отдельными записями; без времени нельзя указать, какие входы были после лимита','Counts separate records, including quick entries. Partial fills may be separate records; without timestamps the entries after the limit cannot be identified'),L('Откройте день и запишите, почему решили продолжить; при частичных закрытиях сначала сверьте число самостоятельных сделок','Open the day and note why you continued; for partial closes, first check the number of separate trades'),x.rows);}
    if(lossDays.length){const x=lossDays.at(-1);add('daily_limit_'+x.date,'warn',L(`${x.date}: дневной net-итог ${money(x.pnl)} при личном лимите $${num(x.rule.dailyLoss).toFixed(2)}`,`${x.date}: daily net total ${money(x.pnl)} against your loss limit of $${num(x.rule.dailyLoss).toFixed(2)}`),L(`Без P&L: ${x.unknown}. Часовой пояс: ${x.rule.timezone}`,`Without P&L: ${x.unknown}. Time zone: ${x.rule.timezone}`),L('Это net по известным закрытым записям, не сумма всех убытков и не внутридневная просадка. Пустые расходы или P&L делают вывод предварительным','This is net across known closed records, not the sum of all losses or intraday drawdown. Missing costs or P&L make this preliminary'),L('Откройте день и сверьте записи с вашим правилом остановки. Порядок продолжения после лимита не установлен','Open the day and compare the records with your stopping rule. Continuing after the limit has not been established'),x.rows);}
    const above=list.filter(t=>{const s=t.riskSnapshot;if(s?.confirmed!==true||!(num(s.capital)>0)||!(num(s.maxPct)>0)||!(num(s.riskUsd)>0))return false;
      const p=position({...s,riskPct:100,maxPct:null});
      const recomputed=p.unit*num(s.size);return Number.isFinite(recomputed)&&Math.abs(recomputed-num(s.riskUsd))<.02&&num(s.riskUsd)/num(s.capital)*100>num(s.maxPct)+1e-8;
    });
    if(above.length){const s=above.at(-1).riskSnapshot;add('risk_limit','warn',L(`Записанный плановый риск ${(s.riskUsd/s.capital*100).toFixed(2)}% при личном максимуме ${num(s.maxPct)}%`,`Recorded planned risk ${(s.riskUsd/s.capital*100).toFixed(2)}% against your maximum of ${num(s.maxPct)}%`),L(`Таких записей: ${above.length}; используется снимок расчёта на момент подтверждения`,`${above.length} such ${above.length===1?'record':'records'}; uses the calculation snapshot when confirmed`),L('Проверка относится к подтверждённому плановому размеру, не к убытку после закрытия. Проскальзывание и неизвестные расходы не предсказаны','Checks the confirmed planned size, not the loss after closing. Slippage and unknown costs are not predicted'),L('Проверьте использованный размер и стоп по сохранённому расчёту; перед новым входом сверяйте расчёт с личным максимумом','Check the size used and stop against the saved calculation; before a new entry compare it with your own maximum'),above);}
    const a=prefs.action;
    if(a?.id&&a.text){const all=list.filter(t=>context(t,a)&&t.date>=a.sinceDay),assessed=all.filter(t=>t.learning?.actionId===a.id&&typeof t.learning.actionDone==='boolean');
      if(assessed.length){const yes=assessed.filter(t=>t.learning.actionDone).length;add('action_progress','info',L(`Ваше действие: выполнено в ${yes} из ${assessed.length} ${assessed.length%10===1&&assessed.length%100!==11?'оценённой записи':'оценённых записей'}`,`Your action: completed in ${yes} of ${assessed.length} assessed ${assessed.length===1?'record':'records'}`),L(`${a.text}; без оценки: ${all.length-assessed.length}`,`${a.text}; not assessed: ${all.length-assessed.length}`),L('Выполнение считается по вашему явному ответу, а не по прибыли или отсутствию отметки ошибки','Completion uses your explicit answer, not profit or the absence of a mistake mark'),L('Разберите невыполненные случаи и уточните, что мешало сделать проверку','Review the uncompleted cases and identify what prevented the check'),assessed.filter(t=>!t.learning.actionDone));}}
    return out;
  }
  return {day,ruleAt,parseRR,modelR,position,realisedR,cards};
});
