'use strict';
// Shared presentation components. No network calls, permissions or fleet state.
window.PatchyUI=(()=>{
 const esc=s=>String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
 const icons={
  overview:'<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
  servers:'<rect x="3" y="3" width="18" height="7" rx="2"/><rect x="3" y="14" width="18" height="7" rx="2"/><path d="M7 6.5h.01M7 17.5h.01M15 6.5h3M15 17.5h3"/>',
  packages:'<path d="m12 3 9 5v9l-9 5-9-5V8l9-5Zm0 10v9M3 8l9 5 9-5M7.5 5.5l9 5"/>',
  repositories:'<path d="M4 7h15m-4-4 4 4-4 4M20 17H5m4-4-4 4 4 4"/>',
  investigations:'<circle cx="10.5" cy="10.5" r="7.5"/><path d="m16 16 5 5M8 10.5h5m-2.5-2.5v5"/>',
  schedules:'<rect x="3" y="5" width="18" height="16" rx="3"/><path d="M7 3v4m10-4v4M3 11h18m-13 5h2m4 0h2"/>',
  activity:'<path d="M3 12h4l3-8 4 16 3-8h4"/>',
  settings:'<path d="M4 7h16M4 17h16"/><circle cx="9" cy="7" r="3"/><circle cx="16" cy="17" r="3"/>',
  shield:'<path d="m12 3 8 3v6c0 5-8 9-8 9s-8-4-8-9V6l8-3Z"/><path d="m8 12 3 3 5-6"/>',
  arrow:'<path d="M5 12h14m-6-6 6 6-6 6"/>',
  refresh:'<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6 7a7 7 0 0 1 12-1l2 3M4 15l2 3a7 7 0 0 0 12-1"/>'
 };
 const pages={security:['Security coverage','A clearer view of every check.'],users:['Users','Good company. Clear permissions.'],history:['Package history','Every patch leaves a footprint.'],'ai-logs':['AI run logs','A closer look at the work.'],overview:['Overview','Your fleet, in good paws.'],servers:['Server fleet','A home for every machine.'],packages:['Package inventory','Every package. Every patch.'],repositories:['Repository sources','Good updates start at the source.'],investigations:['AI investigations','A curious raccoon. A closer look.'],schedules:['Patch schedules','A little planning goes a long way.'],activity:['Activity & audit','Follow every footprint.'],settings:['Workspace settings','Make yourself at home.']};
 const icon=name=>`<svg class="icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name]||icons.shield}</svg>`;
 const mascot=(pose='welcome',className='',alt='')=>`<img class="mascot ${className}" src="/static/mascot/mr-patchy-${pose==='working'?'working':'welcome'}.png" alt="${alt}" width="${pose==='working'?1536:1218}" height="${pose==='working'?1024:1292}" decoding="async">`;
 const portrait=()=>`<span class="mascot-portrait" aria-hidden="true">${mascot()}</span>`;
 function heading(page,title,sub,button=''){
  const meta=pages[page]||pages.overview;
  return `<section class="heading ${page==='overview'?'heading-overview':''}" aria-labelledby="page-title"><div class="heading-copy"><div class="eyebrow">${icon(page)} ${meta[0]}</div><h1 id="page-title" tabindex="-1">${title}</h1><p>${sub}</p>${button?`<div class="heading-actions">${button}</div>`:''}</div><div class="heading-mascot" aria-hidden="true">${mascot(page==='overview'?'working':'welcome')}<span class="mascot-caption">${meta[1]}</span></div></section>`;
 }
 const empty=(title,text,action='')=>`<div class="empty">${mascot('welcome','empty-mascot')}<div><span class="eyebrow">MR PATCHY'S WORKBENCH</span><h3>${title}</h3><p>${text}</p>${action}</div></div>`;
 const loading=()=>`<div class="loading-state" role="status">${portrait()}<div><strong>Mr Patchy is checking in…</strong><p>Gathering your workspace.</p></div><span class="loading-dots" aria-hidden="true">•••</span></div>`;
 const enrollment=step=>`<ol class="enrollment-steps" aria-label="Enrollment progress">${['Server details','Prepare target','Connect & verify'].map((label,index)=>`<li class="${index+1===step?'current':index+1<step?'done':''}" ${index+1===step?'aria-current="step"':''}><span>${index+1<step?'✓':index+1}</span>${label}</li>`).join('')}</ol>`;
 // Shared route-link navigation, using native disclosure rather than a simulated ARIA menu.
 function sectionNavigation(entries,current,link,primary,groups){
  const anchor=entry=>`<a href="${esc(link(entry[0]))}" ${entry[0]===current?'class="active" aria-current="page"':''}>${esc(entry[1])}</a>`;
  const secondary=entries.filter(entry=>!primary.includes(entry[0]));
  const selected=secondary.find(entry=>entry[0]===current);
  return primary.map(key=>entries.find(entry=>entry[0]===key)).filter(Boolean).map(anchor).join('')+(secondary.length?`
   <details class="section-menu ${selected?'has-current':''}"><summary><span>${selected?esc(selected[1])+' · ':''}More sections</span>${icon('overview')}</summary>
    <div class="section-menu-panel"><div class="section-menu-intro">${portrait()}<div><strong>Your server workbench</strong><small>Choose a focused workspace</small></div></div>
    <div class="section-menu-groups">${groups.map(group=>{const items=secondary.filter(entry=>group.ids.includes(entry[0]));return items.length?`<section><h3>${esc(group.title)}</h3>${items.map(anchor).join('')}</section>`:'';}).join('')}</div></div>
   </details>`:'');
 }
 document.addEventListener('click',event=>{document.querySelectorAll('.section-menu[open]').forEach(menu=>{if(!menu.contains(event.target)||event.target.closest('a'))menu.open=false;});});
 document.addEventListener('keydown',event=>{if(event.key!=='Escape')return;const menu=event.target.closest('.section-menu[open]');if(menu){menu.open=false;menu.querySelector('summary').focus();event.preventDefault();}});
 document.querySelectorAll('[data-icon]').forEach(node=>node.innerHTML=icon(node.dataset.icon));
 document.querySelectorAll('[data-mascot-portrait]').forEach(node=>node.innerHTML=portrait());
 const endpoint=(address,port)=>{const a=String(address??'');return (a.includes(':')&&!a.startsWith('[')?'['+a+']':a)+(port===undefined||port===null||port===''?'':':'+port);};
 return {esc,icon,mascot,portrait,heading,empty,loading,enrollment,pages,sectionNavigation,endpoint};
})();
