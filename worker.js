/* =========================================================================
   SERVEUR DE LIAISON — version Cloudflare Workers (hébergement gratuit)
   Déploiement : créer un Worker sur dash.cloudflare.com, coller ce fichier,
   puis créer un espace KV nommé SALONS et le lier au Worker.
   L'adresse obtenue (https://xxx.workers.dev) est à saisir dans l'application.
   ========================================================================= */
const RETENTION = 10800;   /* secondes — 3 h */

function cors(){
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type',
    'Content-Type': 'application/json; charset=utf-8'
  };
}
const json = (code, obj) => new Response(JSON.stringify(obj), {status:code, headers:cors()});

export default {
  async fetch(req, env){
    if(req.method === 'OPTIONS') return new Response(null, {status:204, headers:cors()});
    const u = new URL(req.url);
    const chemin = u.pathname.replace(/\/+$/, '') || '/';

    try{
      if(chemin === '/' || chemin === '/sante') return json(200, {ok:true, service:'liaison'});

      if(chemin === '/menu' && req.method === 'POST'){
        const b = await req.json();
        if(!b.s || !b.menu) return json(400, {erreur:'salon ou carte manquant'});
        await env.SALONS.put('menu:'+b.s, JSON.stringify(b.menu), {expirationTtl: 604800});
        return json(200, {ok:true});
      }
      if(chemin === '/menu' && req.method === 'GET'){
        const m = await env.SALONS.get('menu:'+u.searchParams.get('s'));
        if(!m) return json(404, {erreur:'carte introuvable'});
        return json(200, {menu: JSON.parse(m)});
      }

      if(chemin === '/commande' && req.method === 'POST'){
        const b = await req.json();
        if(!b.s || !Array.isArray(b.items) || !b.items.length) return json(400, {erreur:'commande vide'});
        const cle = 'cmd:'+b.s;
        const brut = await env.SALONS.get(cle);
        const list = brut ? JSON.parse(brut) : [];
        const c = {id:'C'+Date.now().toString(36)+Math.random().toString(36).slice(2,5),
                   table:String(b.table||'').slice(0,40), items:b.items.slice(0,60),
                   ts:Date.now(), pris:false};
        list.push(c);
        await env.SALONS.put(cle, JSON.stringify(list.slice(-200)), {expirationTtl: RETENTION});
        return json(200, {ok:true, id:c.id});
      }
      if(chemin === '/commandes' && req.method === 'GET'){
        const brut = await env.SALONS.get('cmd:'+u.searchParams.get('s'));
        const depuis = Number(u.searchParams.get('depuis')) || 0;
        const list = (brut ? JSON.parse(brut) : []).filter(c => !c.pris && c.ts > depuis);
        return json(200, {t:Date.now(), list});
      }
      if(chemin === '/pris' && req.method === 'POST'){
        const b = await req.json();
        const cle = 'cmd:'+b.s;
        const brut = await env.SALONS.get(cle);
        if(brut){
          const list = JSON.parse(brut).map(c => c.id === b.id ? {...c, pris:true} : c);
          await env.SALONS.put(cle, JSON.stringify(list), {expirationTtl: RETENTION});
        }
        return json(200, {ok:true});
      }
      return json(404, {erreur:'route inconnue'});
    }catch(e){
      return json(400, {erreur:String(e.message||e)});
    }
  }
};
