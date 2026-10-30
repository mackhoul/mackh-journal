/* Uses the existing account-scoped document store and JSON trade payload. */
function learningPrefs(){
  if(typeof sdocs==='undefined') return {};
  const d=sdocs['insight-preferences-v1']; return d&&!d.del&&d.data?.purpose==='insights-learning'?d.data:{};
}
function learningTimezone(){
  const p=learningPrefs(),h=p.history||[],latest=h.filter(x=>!x.effectiveDay||x.effectiveDay<=MJLearning.day(Date.now(),x.timezone||'UTC')).at(-1);
  return latest?.timezone||Intl.DateTimeFormat().resolvedOptions().timeZone||'UTC';
}
function journalToday(){return MJLearning.day(Date.now(),learningTimezone());}
function learningText(ru,en){return lang==='ru'?ru:en;}
function learningSavePrefs(p){
  const doc=sdocPut('note',{...p,purpose:'insights-learning'},'insight-preferences-v1');
  if(!doc){toastWarn(learningText('Не удалось сохранить настройки обучения','Could not save learning settings'));return false;}
  renderHome(); return true;
}
function learningStrategyContext(id){
  const s=sdocs[id];
  return {strategyId:id||'',strategyRevId:id?stratEnsureRevision(id):'',strategyName:s?.data?.name||''};
}
function openLearningSettings(){
  const p=learningPrefs(),today=journalToday(),h=MJLearning.ruleAt(p.history,today)||{};
  let box=document.getElementById('learningSettings');
  if(!box){box=document.createElement('section');box.id='learningSettings';box.className='learning-panel';document.querySelector('#settingsModal .mbody').prepend(box);}
  const E=escapeHtml,L=learningText,strategies=sdocAll('strategy',d=>!d.data.archived);
  const opts='<option value="">'+L('Выберите стратегию','Choose a strategy')+'</option>'+strategies.map(s=>`<option value="${E(s.id)}">${E(s.data.name||s.id)}</option>`).join('');
  const mistakes=Object.keys(MISTAKES_LABELS).map(k=>`<option value="${E(k)}">${E(mLabel(k))}</option>`).join('');
  box.innerHTML=`<h3>${L('Обучение и личные лимиты','Learning and personal limits')}</h3>
    <p class="note">${L('Лимиты действуют с указанного дня, без пересчёта старых записей. Новые поля необязательны. Изменения синхронизируются с аккаунтом.','Limits apply from the chosen day without reinterpreting older records. New fields are optional. Changes sync with your account.')}</p>
    <label>${L('Часовой пояс торгового дня (IANA)','Trading-day time zone (IANA)')}<input class="finput" id="lpTimezone" value="${E(h.timezone||learningTimezone())}" placeholder="Europe/Copenhagen"></label>
    <label>${L('Действует с даты','Effective from')}<input class="finput" id="lpDay" type="date" min="${today}" value="${today}"></label>
    <label>${L('Лимит записей за день аккаунта; пусто — без лимита','Account records per day; blank means no limit')}<input class="finput" id="lpCount" type="number" min="1" step="1" value="${E(h.maxTrades||'')}"></label>
    <label>${L('Дневной net-убыток, $; пусто — без лимита','Daily net loss, $; blank means no limit')}<input class="finput" id="lpLoss" type="number" min="0" step="0.01" value="${E(h.dailyLoss||'')}"></label>
    <p class="note">${L('Считаются закрытые записи, включая быстрые. Частичные закрытия могут быть отдельными записями.','Counts closed records, including quick entries. Partial closes may be separate records.')}</p>
    <label>${L('Стратегия для максимума риска и наблюдения','Strategy for the risk maximum and tracking')}<select class="fselect" id="lpStrategy">${opts}</select></label>
    <label>${L('Личный максимум риска на сделку, %; пусто — не задан','Your maximum risk per trade, %; blank means not set')}<input class="finput" id="lpMax" type="number" min="0.001" max="100" step="0.01"></label>
    <p class="note" id="lpRiskHistory"></p>
    <label>${L('Ошибка для наблюдения; пусто — не менять выбор','Mistake to track; blank keeps the current selection')}<select class="fselect" id="lpMistake"><option value="">—</option>${mistakes}</select></label>
    <label>${L('Моё проверяемое действие; пусто — не менять','My checkable action; blank keeps the current action')}<textarea class="ftextarea" id="lpAction" maxlength="400" placeholder="${E(L('Например: сверить условие входа перед сделкой','For example: check my entry condition before the trade'))}"></textarea></label>
    <p class="note">${E(p.action?.text||'')}<br>${E(p.tracking?.key?L('Наблюдение: ','Tracking: ')+mLabel(p.tracking.key):'')}</p>
    <div class="learning-actions"><button type="button" class="insight-trades-btn" id="lpSave">${L('Сохранить правила','Save rules')}</button><button type="button" class="insight-trades-btn" id="lpClearTrack">${L('Завершить наблюдение','End tracking')}</button><button type="button" class="insight-trades-btn" id="lpClearAction">${L('Завершить действие','End action')}</button></div><p role="status" id="lpStatus"></p>`;
  const v=id=>document.getElementById(id),hist=()=>{const sid=v('lpStrategy').value,rs=learningPrefs().risk?.[sid]||[],r=MJLearning.ruleAt(rs,v('lpDay').value);v('lpMax').value=r?.maxPct||'';v('lpRiskHistory').textContent=rs.map(x=>`${x.effectiveDay}: ${x.maxPct===null?L('не задан','not set'):x.maxPct+'%'}`).join(' · ');};
  if(p.tracking?.strategyId&&strategies.some(s=>s.id===p.tracking.strategyId))v('lpStrategy').value=p.tracking.strategyId;
  v('lpStrategy').onchange=hist;v('lpDay').onchange=hist;hist();
  v('lpClearTrack').onclick=()=>{if(learningSavePrefs({...learningPrefs(),tracking:null})){openLearningSettings();v('lpStatus').textContent=L('Наблюдение завершено; старые оценки сохранены','Tracking ended; previous assessments are kept');}};
  v('lpClearAction').onclick=()=>{if(learningSavePrefs({...learningPrefs(),action:null})){openLearningSettings();v('lpStatus').textContent=L('Действие завершено; старые оценки сохранены','Action ended; previous assessments are kept');}};
  v('lpSave').onclick=()=>{
    try{
      const timezone=v('lpTimezone').value.trim(),effectiveDay=v('lpDay').value,sid=v('lpStrategy').value;
      MJLearning.day(Date.now(),timezone);
      if(!/^\d{4}-\d{2}-\d{2}$/.test(effectiveDay)||effectiveDay<journalToday())throw Error(L('Выберите сегодняшний или будущий день','Choose today or a future day'));
      const positive=(id,max,integer=false)=>{const raw=v(id).value;if(!raw)return null;const n=Number(raw);if(!(n>0)||!Number.isFinite(n)||n>max||(integer&&!Number.isInteger(n)))throw Error(L('Проверьте лимиты: нужны положительные числа','Check the limits: positive numbers are required'));return n;};
      const maxTrades=positive('lpCount',10000,true),dailyLoss=positive('lpLoss',1e12),maxPct=positive('lpMax',100);
      if((v('lpMistake').value||v('lpAction').value.trim()||maxPct!==null)&&!sid)throw Error(L('Сначала выберите стратегию','Choose a strategy first'));
      const savedAt=new Date().toISOString(),next={...learningPrefs()},context=learningStrategyContext(sid);
      next.history=[...(next.history||[]),{effectiveDay,timezone,maxTrades,dailyLoss,savedAt}];
      next.risk={...(next.risk||{})};if(sid)next.risk[sid]=[...(next.risk[sid]||[]),{effectiveDay,maxPct,savedAt,strategyRevId:context.strategyRevId}];
      const key=v('lpMistake').value,text=v('lpAction').value.trim();
      if(key)next.tracking={...context,id:sdocUid('track'),key,labelRu:MISTAKES_LABELS[key]?.ru||key,labelEn:MISTAKES_LABELS[key]?.en||key,sinceDay:effectiveDay};
      if(text)next.action={...context,id:sdocUid('action'),text,sinceDay:effectiveDay};
      if(learningSavePrefs(next)){openLearningSettings();v('lpStatus').textContent=L('Сохранено на устройстве; статус синхронизации — в разделе стратегий','Saved on this device; sync status is shown in Strategies');}
    }catch(e){v('lpStatus').textContent=e.message||L('Проверьте настройки','Check the settings');}
  };
}
function openLearningFromInsight(id){
  const i=(window._currentInsights||[]).find(x=>x.id===id),suggested=i?.act||'';
  closeModal('insightDetailModal');openSettings();
  const linked=(i?.tradeIds||[]).map(id=>trades.find(t=>t.id===id)).filter(Boolean);
  const strategyId=linked[0]?.strategyId;
  if(strategyId&&linked.every(t=>t.strategyId===strategyId)){
    document.getElementById('lpStrategy').value=strategyId;document.getElementById('lpStrategy').onchange();
  }
  if(suggested)document.getElementById('lpAction').value=suggested;
}
function learningFieldHTML(prefix,trade){
  const p=learningPrefs(),L=learningText,E=escapeHtml,old=trade?.learning||{};
  const strategy=document.getElementById(prefix+'Strategy')?.value||'';
  // Use the same revision rule as stratTradeLink when saving: edits keep their original link. Drawing
  // only looks the current revision up; saving the trade creates it when the rules changed.
  const revision=strategy?(trade?.strategyId===strategy?trade.strategyRevId||'':stratCurrentRevision(strategy)||''):'';
  // the same day rule as readLearningTrade: an answer is offered only where saving keeps it
  const date=document.getElementById(prefix+'Date')?.value||journalToday();
  const sameRules=c=>c&&c.strategyId===strategy&&(c.strategyRevId||'')===revision;
  const fits=c=>sameRules(c)&&date>=c.sinceDay;
  const stale=[p.tracking,p.action].some(c=>c&&c.strategyId===strategy&&!sameRules(c));
  const early=[p.tracking,p.action].filter(c=>sameRules(c)&&date<c.sinceDay).map(c=>c.sinceDay).sort()[0];
  const sel=(id,text,value,key)=>`<label>${E(text)}<select class="fselect" id="${id}" data-learn-for="${E(key)}"><option value="">${L('Не оценено','Not assessed')}</option><option value="yes" ${value===true?'selected':''}>${L('Да','Yes')}</option><option value="no" ${value===false?'selected':''}>${L('Нет','No')}</option></select></label>`;
  return `<summary>${L('Моя работа над ошибками — необязательно','Learning from my mistakes — optional')}</summary><div class="learning-panel">
    <p class="note">${L('Ответы не выводятся из прибыли или убытка. Настройте выбранную ошибку и действие в настройках аккаунта.','Answers are not inferred from profit or loss. Choose a mistake and action in account settings.')}</p>
    ${prefix==='q'?'<p class="note">'+L('Если известен первоначальный риск, после сохранения добавьте его через редактирование этой сделки в полной форме. Тип быстрой записи сохранится.','If the original risk is known, add it after saving by editing this trade in the full form. It will remain a quick-entry record.')+'</p>':''}
    <p class="note">${L('Наблюдение относится к выбранной стратегии и её редакции на дату начала. После изменения правил начните новое наблюдение.','Tracking belongs to the selected strategy and its revision when tracking started. Start new tracking after changing the rules.')}</p>
    ${stale?'<p class="note">'+L('Выбрана другая редакция правил. Начните новое наблюдение или действие для этой редакции в настройках.','A different rules revision is selected. Start new tracking or an action for this revision in settings.')+'</p>':''}
    ${early?'<p class="note">'+E(L('Наблюдение действует с '+early+'. Для записи с более ранней датой ответ не сохраняется.','Tracking applies from '+early+'. For a record with an earlier date, the answer is not saved.'))+'</p>':''}
    ${fits(p.tracking)?sel(prefix+'LearnError',L('Была выбранная ошибка: ','Was the selected mistake present: ')+mLabel(p.tracking.key)+'?',old.trackingId===p.tracking.id?old.errorPresent:undefined,'track:'+p.tracking.id):''}
    ${fits(p.action)?sel(prefix+'LearnAction',L('Выполнили действие: ','Did you complete: ')+p.action.text+'?',old.actionId===p.action.id?old.actionDone:undefined,'action:'+p.action.id):''}
    <button type="button" class="insight-trades-btn" onclick="openSettings()">${L('Настроить наблюдение','Set up tracking')}</button></div>`;
}
function renderLearningTrade(prefix,trade){
  const anchor=document.getElementById(prefix==='t'?'tNotes':'qNotes');if(!anchor)return;
  let box=document.getElementById(prefix+'Learning');if(!box){box=document.createElement('details');box.id=prefix+'Learning';box.className='learning-fold';anchor.closest('.fgroup').after(box);}
  // The full form calls this on every step (stepNext → syncStateToForm). Draw once per opened form —
  // every open makes a new tForm — so moving between the steps keeps what was typed here.
  if(prefix==='t'&&box.learningForm===tForm&&box.innerHTML)return;
  box.learningForm=prefix==='t'?tForm:null;box.learningTrade=trade;box.learningDraft={};
  box.innerHTML=learningFieldHTML(prefix,trade);
  const selector=document.getElementById(prefix+'Strategy');
  // bound once per page: it reads the trade of the form open now, not the one of the first open
  if(selector&&!selector.dataset.learningBound){selector.dataset.learningBound='1';selector.addEventListener('change',()=>{learningRedrawAnswers(prefix);if(prefix==='t'){calcPosition();learningRiskPreview();}});}
  // a new date can move the record before or after the start of tracking: the questions follow it
  const day=document.getElementById(prefix+'Date');
  if(day&&!day.dataset.learningBound){day.dataset.learningBound='1';day.addEventListener('change',()=>learningRedrawAnswers(prefix));}
  if(prefix==='t')renderLearningRisk(trade);
}
// Values typed in learning fields, kept across a redraw (an empty answer stays empty)
function learningKeep(ids){
  const out={};ids.forEach(id=>{const e=document.getElementById(id);if(e)out[id]=e.type==='checkbox'?e.checked:e.value;});return out;
}
function learningPut(typed){
  Object.entries(typed).forEach(([id,x])=>{const e=document.getElementById(id);if(!e)return;if(e.type==='checkbox')e.checked=x;else e.value=x;});
}
// Answers typed in the open form are a draft kept by the tracking or action they answer (data-learn-for).
// A redraw for a date, strategy or language change may hide a question; when it shows again, the
// typed answer comes back. An answer never moves to another tracking, and a hidden one is not saved.
function learningRedrawAnswers(prefix){
  const box=document.getElementById(prefix+'Learning');if(!box?.innerHTML)return;
  const draft=box.learningDraft||(box.learningDraft={}),ids=[prefix+'LearnError',prefix+'LearnAction'];
  ids.forEach(id=>{const e=document.getElementById(id);if(e?.dataset.learnFor)draft[e.dataset.learnFor]=e.value;});
  box.innerHTML=learningFieldHTML(prefix,box.learningTrade);
  ids.forEach(id=>{const e=document.getElementById(id),key=e?.dataset.learnFor;if(key&&Object.prototype.hasOwnProperty.call(draft,key))e.value=draft[key];});
}
// A language switch (applyLang) draws the open learning blocks again in the new language and keeps
// what was typed but not saved yet: the settings fields, the answers and the confirmed-size fields.
function relangLearning(){
  const v=id=>document.getElementById(id);
  if(v('learningSettings')?.innerHTML&&v('lpStrategy')){
    const typed=learningKeep(['lpTimezone','lpDay','lpCount','lpLoss','lpStrategy','lpMax','lpMistake','lpAction']);
    openLearningSettings();
    learningPut({lpStrategy:typed.lpStrategy,lpDay:typed.lpDay});v('lpStrategy').onchange();   // the risk history in the new language
    learningPut(typed);
  }
  ['t','q'].forEach(learningRedrawAnswers);
  const risk=v('tLearningRisk');
  if(risk?.innerHTML){
    const typed=learningKeep(['lrCapital','lrSize','lrMultiplier','lrStep','lrMinimum','lrFeeIn','lrFeeOut','lrConfirm']);
    const dirty=risk.dataset.dirty,original=risk.dataset.original;
    renderLearningRisk(v('tLearning')?.learningTrade||null);
    learningPut(typed);risk.dataset.dirty=dirty;risk.dataset.original=original;learningRiskPreview();
  }
}
function readLearningTrade(prefix,prev,link,date){
  const p=learningPrefs(),old={...(prev?.learning||{})};
  const answer=id=>{const e=document.getElementById(id);return !e||!e.value?null:e.value==='yes';};
  const fits=c=>c&&date>=c.sinceDay&&(c.strategyId||'')===(link.strategyId||'')&&(c.strategyRevId||'')===(link.strategyRevId||'');
  if(fits(p.tracking)){
    const v=answer(prefix+'LearnError');
    if(!old.trackingId||old.trackingId===p.tracking.id||v!==null){
      if(old.trackingId&&old.trackingId!==p.tracking.id)old.history=[...(old.history||[]),{trackingId:old.trackingId,errorKey:old.errorKey,errorPresent:old.errorPresent}];
      old.trackingId=p.tracking.id;old.errorKey=p.tracking.key;old.errorPresent=v;
    }
  }
  if(fits(p.action)){
    const v=answer(prefix+'LearnAction');
    if(!old.actionId||old.actionId===p.action.id||v!==null){
      if(old.actionId&&old.actionId!==p.action.id)old.history=[...(old.history||[]),{actionId:old.actionId,actionDone:old.actionDone}];
      old.actionId=p.action.id;old.actionDone=v;
    }
  }
  return Object.keys(old).length?old:null;
}
function learningMax(strategyId,date){const p=learningPrefs();return MJLearning.ruleAt(p.risk?.[strategyId],date)?.maxPct??null;}
function learningDayPolicy(date){
  const rule=MJLearning.ruleAt(learningPrefs().history,date);
  if(!rule||date<journalToday())return null;
  return {ruleSavedAt:rule.savedAt||null,effectiveDay:rule.effectiveDay,timezone:rule.timezone,maxTrades:rule.maxTrades??null,dailyLoss:rule.dailyLoss??null};
}
function renderLearningRisk(trade){
  let box=document.getElementById('tLearningRisk');if(!box){box=document.createElement('details');box.id='tLearningRisk';box.className='learning-fold';document.getElementById('tLearning').after(box);}
  const E=escapeHtml,L=learningText,s=trade?.riskSnapshot||{},field=(id,label,value,step='any')=>`<label>${label}<input class="finput" type="number" id="lr${id}" step="${step}" value="${E(value??'')}"></label>`;
  box.innerHTML=`<summary>${L('Подтвердить использованный плановый размер — необязательно','Confirm the planned size used — optional')}</summary><div class="learning-panel">
    <p class="note">${L('Это первоначальный плановый риск, не размер убытка. Заполняйте только известные параметры. Формула линейного контракта; неизвестный курс/контракт не оценивается.','This is the original planned risk, not the loss amount. Enter only known parameters. Uses a linear-contract formula; unknown conversion rates or contracts cannot be assessed.')}</p>
    <div class="learning-grid">${field('Capital',L('Капитал при входе, $','Capital at entry, $'),s.capital??(baseCapital>0?computeCapital():''))}${field('Size',L('Использованный объём (единицы/лоты)','Size used (units/lots)'),s.size)}${field('Multiplier',L('$ за единицу движения × единицу объёма','$ per price move × unit of size'),s.multiplier)}${field('Step',L('Шаг объёма','Size step'),s.step)}${field('Minimum',L('Минимальный объём','Minimum size'),s.minimum)}${field('FeeIn',L('Комиссия входа, %; 0 — нет','Entry fee, %; 0 means none'),s.feeEntry===undefined?'':s.feeEntry*100)}${field('FeeOut',L('Комиссия выхода, %; 0 — нет','Exit fee, %; 0 means none'),s.feeExit===undefined?'':s.feeExit*100)}</div>
    <label><input type="checkbox" id="lrConfirm" ${s.confirmed?'checked':''}> ${L('Подтверждаю использованный размер, исходный стоп и параметры','I confirm the size used, original stop and parameters')}</label>
    <p class="note" id="lrPreview"></p></div>`;
  box.dataset.original=JSON.stringify(s);box.dataset.dirty='';
  box.oninput=()=>{box.dataset.dirty='1';learningRiskPreview();};learningRiskPreview();
}
function readLearningRisk(prev,link,date){
  const box=document.getElementById('tLearningRisk'),confirm=document.getElementById('lrConfirm');
  if(!box||!confirm)return prev?.riskSnapshot||null;
  if(!box.dataset.dirty&&prev?.riskSnapshot)return prev.riskSnapshot;
  if(!confirm.checked)return null;
  const get=id=>{const raw=document.getElementById('lr'+id).value;return raw===''?NaN:Number(raw);};
  const s={capital:get('Capital'),size:get('Size'),multiplier:get('Multiplier'),step:get('Step'),minimum:get('Minimum'),feeEntry:get('FeeIn')/100,feeExit:get('FeeOut')/100,
    entry:Number(document.getElementById('tEntry').value),stop:Number(document.getElementById('tSL').value),dir:tForm.dir||'buy'};
  if(![s.capital,s.size,s.multiplier,s.step,s.minimum,s.entry,s.stop].every(x=>Number.isFinite(x)&&x>0)||![s.feeEntry,s.feeExit].every(x=>Number.isFinite(x)&&x>=0))throw Error(learningText('Заполните известные параметры риска и комиссии (0 — без комиссии)','Fill in the known risk parameters and fees (0 means no fee)'));
  const p=MJLearning.position({...s,riskPct:100,maxPct:null});
  if(!p.unit||s.size<s.minimum||Math.abs(s.size/s.step-Math.round(s.size/s.step))>1e-7)throw Error(learningText('Проверьте сторону стопа, шаг и минимальный объём','Check the stop side, size step and minimum size'));
  return {...s,confirmed:true,riskUsd:p.unit*s.size,maxPct:learningMax(link.strategyId,date),strategyId:link.strategyId||null,strategyRevId:link.strategyRevId||null,capturedAt:new Date().toISOString(),date};
}
function learningRiskPreview(){
  const e=document.getElementById('lrPreview');if(!e)return;
  try{const sid=document.getElementById('tStrategy').value,link={strategyId:sid,strategyRevId:editingId?trades.find(t=>t.id===editingId)?.strategyRevId:null};const s=readLearningRisk(null,link,document.getElementById('tDate').value||journalToday());
    e.textContent=s?learningText(`Плановый риск $${s.riskUsd.toFixed(2)} (${(s.riskUsd/s.capital*100).toFixed(2)}%). Личный максимум: ${s.maxPct===null?'не задан':s.maxPct+'%'}`,`Planned risk $${s.riskUsd.toFixed(2)} (${(s.riskUsd/s.capital*100).toFixed(2)}%). Your maximum: ${s.maxPct===null?'not set':s.maxPct+'%'}`):learningText('Без подтверждения риск останется неизвестным','Without confirmation, risk remains unknown');
  }catch(err){e.textContent=err.message;}
}
function learningRealisedR(t){
  if(tradeCostsPending(t))return null;
  return MJLearning.realisedR({...t,netPnl:tradeNet(t)});
}
function learningRiskDetails(t){
  const s=t.riskSnapshot;if(s?.confirmed!==true||!(Number(s.riskUsd)>0))return '';
  const r=learningRealisedR(t),L=learningText,E=escapeHtml;
  return '<div class="dblock"><div class="dblock-title">'+L('Подтверждённый первоначальный риск','Confirmed original risk')+'</div><p class="note">'+E('$'+Number(s.riskUsd).toFixed(2)+(Number(s.capital)>0?' ('+(s.riskUsd/s.capital*100).toFixed(2)+'%)':''))+'</p><p>'+E(L('Реализованный результат: ','Realised outcome: ')+(r===null?L('неизвестен','unknown'):(r>0?'+':'')+r.toFixed(2)+'R'))+'</p><p class="note">'+L('Фактический net-итог / подтверждённый первоначальный денежный риск. Это отдельно от условной модели по плановому R:R.','Actual net outcome / confirmed original monetary risk. This is separate from the planned-R:R model.')+'</p></div>';
}
