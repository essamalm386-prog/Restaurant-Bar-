/* =========================================================================
   JARABA — Worker unique : serveur de liaison + tunnel de vente autonome
   -------------------------------------------------------------------------
   Déploiement : ce fichier remplace worker.js dans le dépôt GitHub connecté
   à Cloudflare. Le binding KV « SALONS » sert aux deux usages, avec des
   préfixes de clés distincts (liaison éphémère / ventes durables).

   Un seul secret est nécessaire (Settings → Variables and Secrets → Add) :
     ADMIN_CLE   mot de passe de votre tableau de bord de ventes.
                 Sans lui la boutique vend normalement ; seul le tableau
                 de bord reste inaccessible.

   Facultatifs : LIC_SEL, MOMO_NUMERO, MOMO_NOM, SITE_VENTE remplacent les
   valeurs ci-dessous. CINETPAY_KEY et CINETPAY_SITE, s'ils sont renseignés,
   font basculer la boutique du règlement direct vers l'encaissement automatique.
   ========================================================================= */

const RETENTION = 10800;            /* liaison : 3 h */
const CP_API    = 'https://api-checkout.cinetpay.com/v2';

/* ---- Catalogue commercial : modifiable sans toucher au reste ------------ */
const FORMULES = {
  m1:  { mois: 1,  prix: 1000,  titre: '1 mois' },
  m6:  { mois: 6,  prix: 5000,  titre: '6 mois' },
  m12: { mois: 12, prix: 10000, titre: '12 mois' },
  m24: { mois: 24, prix: 15000, titre: '2 ans' }
};
const DEVISE = 'XAF';
const BONUS_FILLEUL = 1;            /* mois offerts à celui qui utilise un code */
const BONUS_PARRAIN  = 1;            /* mois offerts à celui qui l'a donné */

/* Coordonnées d'encaissement. Publiques par nature : elles s'affichent sur la
   boutique. Les secrets MOMO_NUMERO / MOMO_NOM les remplacent si définis. */
const MOMO_DEFAUT = { numero: '655 01 47 92', nom: 'Louis Marie ESSAMA' };

/* Adresse de la boutique, où le client est renvoyé après paiement.
   Publique elle aussi ; le secret SITE_VENTE la remplace si besoin. */
const SITE_DEFAUT = 'https://effortless-bonbon-5dd272.netlify.app';

/* ------------------------------------------------------------------ */
/*  Utilitaires                                                        */
/* ------------------------------------------------------------------ */
const cors = () => ({
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Content-Type': 'application/json; charset=utf-8'
});
/* Rien n'est mis en cache par défaut : une carte, une file de commandes ou un
   contrôle de configuration périmés induiraient en erreur plus qu'ils n'aident.
   Seules les photos de la carte font exception, plus bas. */
const json = (code, obj) => new Response(JSON.stringify(obj),
  { status: code, headers: { ...cors(), 'Cache-Control': 'no-store, max-age=0' } });
const html = (code, s) => new Response(s, {
  status: code,
  headers: { 'Content-Type': 'text/html; charset=utf-8', 'Cache-Control': 'no-store' }
});

/* =========================================================================
   EMPREINTE DU SALON — copie mot pour mot de app-empreinte.js

   Le salon d'un bar est l'empreinte SHA-256 de sa clé privée. Les deux côtés
   doivent calculer exactement la même chose : ce bloc est donc identique à
   celui embarqué dans l'application. Ne le modifier que des deux côtés à la
   fois, sinon plus aucun bar ne peut publier sa carte.
   ========================================================================= */
var SHA_K = [
  0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
  0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
  0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
  0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
  0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
  0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
  0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
  0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
];

/* UTF-8 explicite plutôt que le vieux couple unescape/encodeURIComponent :
   celui-ci n'existe pas partout et se comporte différemment selon les
   environnements. Ici, un caractère donne toujours les mêmes octets. */
function octetsUTF8(s){
  var u = [], i, c, c2, cp;
  for(i = 0; i < s.length; i++){
    c = s.charCodeAt(i);
    if(c < 0x80) u.push(c);
    else if(c < 0x800) u.push(0xc0 | (c >> 6), 0x80 | (c & 63));
    else if(c >= 0xd800 && c < 0xdc00 && i + 1 < s.length){
      c2 = s.charCodeAt(++i);
      cp = 0x10000 + ((c & 0x3ff) << 10) + (c2 & 0x3ff);
      u.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 63),
             0x80 | ((cp >> 6) & 63), 0x80 | (cp & 63));
    }
    else u.push(0xe0 | (c >> 12), 0x80 | ((c >> 6) & 63), 0x80 | (c & 63));
  }
  return u;
}

function sha256(message){
  var u = octetsUTF8(String(message)), i;

  var bits = u.length * 8;
  u.push(0x80);
  while(u.length % 64 !== 56) u.push(0);
  /* longueur sur 64 bits ; nos messages font quelques dizaines d'octets,
     les 32 bits de poids fort sont donc toujours nuls */
  u.push(0, 0, 0, 0);
  u.push((bits >>> 24) & 0xff, (bits >>> 16) & 0xff, (bits >>> 8) & 0xff, bits & 0xff);

  var h = [0x6a09e667,0xbb67ae85,0x3c6ef372,0xa54ff53a,
           0x510e527f,0x9b05688c,0x1f83d9ab,0x5be0cd19];
  var w = new Array(64);

  function droite(x, n){ return (x >>> n) | (x << (32 - n)); }

  for(var bloc = 0; bloc < u.length; bloc += 64){
    for(i = 0; i < 16; i++)
      w[i] = (u[bloc+i*4] << 24) | (u[bloc+i*4+1] << 16) | (u[bloc+i*4+2] << 8) | u[bloc+i*4+3];
    for(i = 16; i < 64; i++){
      var s0 = droite(w[i-15],7) ^ droite(w[i-15],18) ^ (w[i-15] >>> 3);
      var s1 = droite(w[i-2],17) ^ droite(w[i-2],19) ^ (w[i-2] >>> 10);
      w[i] = (w[i-16] + s0 + w[i-7] + s1) | 0;
    }
    var a=h[0], b=h[1], c=h[2], d=h[3], e=h[4], f=h[5], g=h[6], x=h[7];
    for(i = 0; i < 64; i++){
      var S1 = droite(e,6) ^ droite(e,11) ^ droite(e,25);
      var ch = (e & f) ^ (~e & g);
      var t1 = (x + S1 + ch + SHA_K[i] + w[i]) | 0;
      var S0 = droite(a,2) ^ droite(a,13) ^ droite(a,22);
      var maj = (a & b) ^ (a & c) ^ (b & c);
      var t2 = (S0 + maj) | 0;
      x=g; g=f; f=e; e=(d + t1)|0; d=c; c=b; b=a; a=(t1 + t2)|0;
    }
    h[0]=(h[0]+a)|0; h[1]=(h[1]+b)|0; h[2]=(h[2]+c)|0; h[3]=(h[3]+d)|0;
    h[4]=(h[4]+e)|0; h[5]=(h[5]+f)|0; h[6]=(h[6]+g)|0; h[7]=(h[7]+x)|0;
  }

  var hex = '';
  for(i = 0; i < 8; i++) hex += ('00000000' + (h[i] >>> 0).toString(16)).slice(-8);
  return hex;
}

/* L'alphabet des salons : ni 0/o, ni 1/l, pour qu'un identifiant reste
   lisible à voix haute et recopiable sans erreur. */
var ALPHABET_SALON = 'abcdefghijkmnpqrstuvwxyz23456789';

/* L'empreinte publique d'une clé privée : douze caractères, comme avant.
   C'est elle qui voyage dans les QR de table. */
function empreinteSalon(cle){
  var hex = sha256('jaraba-salon-v1|' + String(cle));
  var s = '';
  for(var i = 0; i < 12; i++)
    s += ALPHABET_SALON.charAt(parseInt(hex.substr(i * 2, 2), 16) % 32);
  return s;
}

/* Le contrôle qui ferme la porte : le QR d'une table ne porte que
   l'empreinte. Sans la clé, on lit la carte et on commande — rien de plus. */
function salonAutorise(salon, cle) {
  if (!salon || !cle) return false;
  return empreinteSalon(String(cle)) === String(salon);
}

/* Reproduit EXACTEMENT le hachage du générateur de licences.
   La multiplication dépasse volontairement 2^53 : ne pas « corriger »
   en Math.imul, sinon les clés produites ne seraient plus reconnues. */
function hashStr(str) {
  let h1 = 0x811c9dc5, h2 = 0x01000193;
  for (let i = 0; i < str.length; i++) {
    const c = str.charCodeAt(i);
    h1 = (h1 ^ c) >>> 0; h1 = (h1 * 0x01000193) >>> 0;
    h2 = ((h2 << 5) + h2 + c) >>> 0;
  }
  return h1.toString(16).toUpperCase().padStart(8, '0')
       + h2.toString(16).toUpperCase().padStart(8, '0');
}
function b64enc(str) {
  const o = new TextEncoder().encode(str);
  let bin = '';
  for (let i = 0; i < o.length; i++) bin += String.fromCharCode(o[i]);
  return btoa(bin).replace(/=+$/, '');
}
/* Une licence court jusqu'à la FIN d'un mois : c'est la granularité du format. */
function moisPlus(n) {
  const d = new Date();
  d.setMonth(d.getMonth() + n);
  return d.getFullYear() + '-' + String(d.getMonth() + 1).padStart(2, '0');
}
function fabriquerCle(sel, client, exp) {
  const sig = hashStr(sel + '|' + client.toUpperCase() + '|' + exp).slice(0, 10);
  return 'BARLIC.' + b64enc(JSON.stringify([client, exp, sig]));
}

function hash32(str, graine) {
  let h = graine >>> 0;
  for (let i = 0; i < str.length; i++) {
    h ^= str.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  h ^= h >>> 16; h = Math.imul(h, 0x7feb352d) >>> 0;
  h ^= h >>> 15; h = Math.imul(h, 0x846ca68b) >>> 0;
  return (h ^ (h >>> 16)) >>> 0;
}
/* Empreinte du sel attendu. Ce n'est pas le sel : on ne peut pas le
   reconstituer à partir d'elle, mais elle permet au Worker de vérifier
   qu'il détient le bon. Sans cette garde, un secret absent ou collé avec
   une espace produisait des clés d'apparence normale, que l'application
   refusait ensuite sans que personne comprenne pourquoi. */
const SEL_EMPREINTE = '76D8C994';
function empreinte(sel) {
  return hash32(sel, 0x5eed1234).toString(16).toUpperCase().padStart(8, '0');
}

/* Le sel figure déjà dans chaque copie de l'application vendue : le garder hors
   de ce fichier ne protégeait rien, et rendait la délivrance des licences
   dépendante d'un réglage de tableau de bord. Il est donc ici, et le secret
   LIC_SEL ne sert plus qu'à le remplacer le jour où on en changera. */
const SEL_DEFAUT = 'BG#K7f93!zQ-2026-CMR';

/* Renvoie le sel utilisable, ou null s'il est incorrect. */
function selUtilisable(env) {
  const sel = String(env.LIC_SEL || SEL_DEFAUT).trim();
  if (!sel || empreinte(sel) !== SEL_EMPREINTE) return null;
  return sel;
}
const ERREUR_SEL = { erreur: "La délivrance des licences est momentanément indisponible. "
                            + "Écrivez-nous, votre demande sera honorée." };
const nettoyerTel = t => String(t || '').replace(/[^\d+]/g, '').slice(0, 20);
const nettoyerNom = n => String(n || '').trim().replace(/[<>|]/g, '').slice(0, 60);
const ref = () => 'JRB' + Date.now().toString(36).toUpperCase()
                 + Math.random().toString(36).slice(2, 6).toUpperCase();
const esc = s => String(s == null ? '' : s)
  .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
/* Selon l'environnement, toLocaleString sépare les milliers par une espace fine
   insécable (U+202F) ou insécable (U+00A0) : on ramène tout à une espace simple. */
const fmtF = n => Number(n || 0).toLocaleString('fr-FR').replace(/[\s\u00a0\u202f]+/g, ' ') + ' F';

/* ---- Parrainage ---------------------------------------------------
   Le code est tiré du numéro : toujours le même pour un client donné,
   sans rien stocker de plus. Alphabet sans 0/O/1/I, dictable au téléphone. */
const ALPHA_CODE = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
/* Hachage propre — surtout pas celui des licences, dont les bits de poids
   faible sont dégradés par la multiplication qui déborde volontairement. */
function codeParrain(tel, variante) {
  const sel = 'parrain|' + tel + (variante ? '|' + variante : '');
  let a = hash32(sel, 0x811c9dc5), b = hash32(sel, 0x9e3779b9), s = '';
  for (let i = 0; i < 3; i++) { s += ALPHA_CODE[a & 31]; a >>>= 5; }
  for (let i = 0; i < 3; i++) { s += ALPHA_CODE[b & 31]; b >>>= 5; }
  return s;
}
/* Attribue le code, en écartant la collision improbable avec un autre numéro. */
async function attribuerCode(env, tel) {
  for (let v = 0; v < 12; v++) {
    const c = codeParrain(tel, v);
    const pris = await env.SALONS.get('v:parr:' + c);
    if (!pris) { await env.SALONS.put('v:parr:' + c, tel); return c; }
    if (pris === tel) return c;
  }
  return codeParrain(tel, Date.now());   /* filet, jamais atteint en pratique */
}
/* Ajoute des mois à une échéance 'AAAA-MM', sans jamais raccourcir. */
function prolonger(exp, mois) {
  const [a, m] = String(exp).split('-').map(Number);
  const d = new Date(Date.UTC(a, m - 1, 1));
  d.setUTCMonth(d.getUTCMonth() + mois);
  return d.getUTCFullYear() + '-' + String(d.getUTCMonth() + 1).padStart(2, '0');
}
/* Récompense le parrain : sa licence gagne des mois, sa nouvelle clé
   l'attend sur la page de parrainage. Il n'a rien à réclamer. */
async function recompenserParrain(env, telParrain, filleul) {
  const brut = await env.SALONS.get('v:tel:' + telParrain);
  if (!brut) return;
  const v = JSON.parse(brut);
  const base = v.exp > moisPlus(0) ? v.exp : moisPlus(0);
  const exp = prolonger(base, BONUS_PARRAIN);
  const sel = selUtilisable(env);
  if (!sel) return;
  const maj = { ...v, exp, cle: fabriquerCle(sel, v.etab, exp) };
  await env.SALONS.put('v:tel:' + telParrain, JSON.stringify(maj));
  const bl = await env.SALONS.get('v:filleuls:' + telParrain);
  const liste = bl ? JSON.parse(bl) : [];
  liste.unshift({ etab: filleul, date: new Date().toISOString(), mois: BONUS_PARRAIN });
  await env.SALONS.put('v:filleuls:' + telParrain, JSON.stringify(liste.slice(0, 200)));
}

/* Index des ventes : une liste légère, suffisante pour un tableau de bord. */
async function ajouterIndex(env, entree) {
  const brut = await env.SALONS.get('v:index');
  const liste = brut ? JSON.parse(brut) : [];
  liste.unshift(entree);
  await env.SALONS.put('v:index', JSON.stringify(liste.slice(0, 2000)));
}

/* ------------------------------------------------------------------ */
/*  Tunnel de vente                                                    */
/* ------------------------------------------------------------------ */

/* Essai gratuit — une seule fois par numéro. Court jusqu'à la fin du mois
   PROCHAIN : tout le monde dispose donc d'au moins trente jours pleins. */
async function essai(req, env) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });

  const deja = await env.SALONS.get('v:essai:' + tel);
  if (deja) {
    const o = JSON.parse(deja);
    return json(200, { cle: o.cle, exp: o.exp, etab: o.etab, rappel: true });
  }
  const sel = selUtilisable(env);
  if (!sel) return json(503, ERREUR_SEL);
  const exp = moisPlus(2).slice(0, 7);          /* fin du mois prochain */
  const cle = fabriquerCle(sel, etab, exp);
  const o = { cle, exp, etab, tel, type: 'essai', date: new Date().toISOString() };
  await env.SALONS.put('v:essai:' + tel, JSON.stringify(o));
  await env.SALONS.put('v:tel:' + tel, JSON.stringify(o));
  await ajouterIndex(env, { ref: 'ESSAI', etab, tel, formule: 'Essai', montant: 0, exp, date: o.date });
  return json(200, { cle, exp, etab });
}

/* Lance un paiement CinetPay et renvoie l'adresse de la page de paiement. */
async function acheter(req, env, origine) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  const f    = FORMULES[b.formule];
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });
  if (!f) return json(400, { erreur: 'Formule inconnue.' });
  if (!env.CINETPAY_KEY || !env.CINETPAY_SITE)
    return json(503, { erreur: "Le paiement n'est pas encore activé. Contactez-nous par WhatsApp." });

  /* Code de parrainage : validé maintenant, honoré à la livraison. */
  let parrainTel = '';
  const code = String(b.parrain || '').trim().toUpperCase();
  if (code) {
    const t = await env.SALONS.get('v:parr:' + code);
    if (t && t !== tel) parrainTel = t;
  }

  const id = ref();
  const site = env.SITE_VENTE || SITE_DEFAUT || origine;
  await env.SALONS.put('v:cmd:' + id,
    JSON.stringify({ id, etab, tel, formule: b.formule, mois: f.mois, montant: f.prix,
                     parrainTel, etat: 'attente', date: new Date().toISOString() }),
    { expirationTtl: 86400 * 7 });

  const r = await fetch(CP_API + '/payment', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      apikey: env.CINETPAY_KEY,
      site_id: env.CINETPAY_SITE,
      transaction_id: id,
      amount: f.prix,
      currency: DEVISE,
      description: 'Jaraba — licence ' + f.titre + ' — ' + etab,
      customer_name: etab,
      customer_phone_number: tel,
      channels: 'ALL',
      notify_url: new URL(req.url).origin + '/vente/notify',
      return_url: site.replace(/\/+$/, '') + '/merci.html?ref=' + id,
      metadata: id
    })
  });
  const j = await r.json().catch(() => ({}));
  const url = j && j.data && j.data.payment_url;
  if (!url) return json(502, { erreur: "Le service de paiement n'a pas répondu. Réessayez.",
                               detail: (j && j.description) || '' });
  return json(200, { url, ref: id });
}

/* Webhook CinetPay. La notification n'est JAMAIS crue sur parole :
   le statut est revérifié en direct auprès de CinetPay avant de livrer. */
async function notify(req, env) {
  let id = '';
  try {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('json')) { const b = await req.json(); id = b.cpm_trans_id || b.transaction_id || ''; }
    else { const f = await req.formData(); id = f.get('cpm_trans_id') || f.get('transaction_id') || ''; }
  } catch (e) { /* corps illisible : on sort proprement */ }
  if (!id) return json(200, { ok: true });

  await livrer(env, String(id));
  return json(200, { ok: true });
}

/* Fabrique et range la licence. Point de passage unique : que le paiement ait
   été confirmé par l'opérateur ou validé à la main, tout aboutit ici. */
async function emettre(env, id) {
  const dejaVendu = await env.SALONS.get('v:paye:' + id);
  if (dejaVendu) return JSON.parse(dejaVendu);
  const brut = await env.SALONS.get('v:cmd:' + id);
  if (!brut) return null;
  const cmd = JSON.parse(brut);

  /* On repart de ce qui reste, jamais du mois courant : racheter tôt ne doit
     jamais raccourcir une licence en cours. */
  const bonus = cmd.parrainTel ? BONUS_FILLEUL : 0;
  const ancien = await env.SALONS.get('v:tel:' + cmd.tel);
  const courant = moisPlus(0);
  let base = courant;
  if (ancien) {
    const prec = JSON.parse(ancien).exp;
    if (prec && prec > base) base = prec;
  }
  const sel = selUtilisable(env);
  if (!sel) return null;                        /* rien plutôt qu'une clé morte */
  const exp = prolonger(base, cmd.mois + bonus);
  const cle = fabriquerCle(sel, cmd.etab, exp);
  const code = await attribuerCode(env, cmd.tel);          /* il peut parrainer à son tour */
  const vente = { ref: id, cle, exp, etab: cmd.etab, tel: cmd.tel,
                  formule: cmd.formule, montant: cmd.montant, bonus,
                  code, date: new Date().toISOString() };
  await env.SALONS.put('v:paye:' + id, JSON.stringify(vente));
  await env.SALONS.put('v:tel:' + cmd.tel, JSON.stringify(vente));
  if (cmd.parrainTel) await recompenserParrain(env, cmd.parrainTel, cmd.etab);
  await ajouterIndex(env, { ref: id, etab: cmd.etab, tel: cmd.tel,
                            formule: (FORMULES[cmd.formule] || {}).titre || cmd.formule,
                            montant: cmd.montant, exp, parraine: !!cmd.parrainTel,
                            mode: cmd.mode || 'auto', date: vente.date });
  return vente;
}

/* Chemin automatique : le statut est revérifié en direct auprès de l'encaisseur
   avant toute livraison. La notification n'est jamais crue sur parole. */
async function livrer(env, id) {
  const dejaVendu = await env.SALONS.get('v:paye:' + id);
  if (dejaVendu) return JSON.parse(dejaVendu);
  const brut = await env.SALONS.get('v:cmd:' + id);
  if (!brut) return null;
  const cmd = JSON.parse(brut);
  if (cmd.mode === 'direct') return null;      /* validation humaine attendue */
  if (!env.CINETPAY_KEY) return null;

  const r = await fetch(CP_API + '/payment/check', {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ apikey: env.CINETPAY_KEY, site_id: env.CINETPAY_SITE, transaction_id: id })
  });
  const j = await r.json().catch(() => ({}));
  const st = (j && j.data && j.data.status) || (j && j.code) || '';
  if (!(st === 'ACCEPTED' || st === '00' || st === 'SUCCES')) return null;

  const montant = Number((j.data && j.data.amount) || 0);
  if (montant && montant < cmd.montant) return null;   /* montant insuffisant : on ne livre pas */
  return emettre(env, id);
}

/* ---- Encaissement direct, sans agrégateur -------------------------
   Le client envoie l'argent sur le Mobile Money du vendeur, puis déclare
   sa référence. Le vendeur confirme d'un geste depuis son tableau de bord
   et la clé part toute seule. Aucune inscription d'entreprise requise. */
async function declarer(req, env) {
  const b = await req.json();
  const etab = nettoyerNom(b.etab);
  const tel  = nettoyerTel(b.tel);
  const f    = FORMULES[b.formule];
  const refPaie = String(b.refPaiement || '').trim().replace(/[<>|]/g, '').slice(0, 40);
  if (!etab) return json(400, { erreur: "Indiquez le nom de votre établissement." });
  if (tel.length < 8) return json(400, { erreur: 'Indiquez un numéro de téléphone valide.' });
  if (!f) return json(400, { erreur: 'Formule inconnue.' });
  if (refPaie.length < 4)
    return json(400, { erreur: "Recopiez l'identifiant du message de confirmation de votre paiement." });

  let parrainTel = '';
  const code = String(b.parrain || '').trim().toUpperCase();
  if (code) {
    const t = await env.SALONS.get('v:parr:' + code);
    if (t && t !== tel) parrainTel = t;
  }
  const id = ref();
  await env.SALONS.put('v:cmd:' + id, JSON.stringify({
    id, etab, tel, formule: b.formule, mois: f.mois, montant: f.prix,
    parrainTel, mode: 'direct', refPaie, etat: 'a-verifier',
    date: new Date().toISOString()
  }), { expirationTtl: 86400 * 30 });

  const bl = await env.SALONS.get('v:attente');
  const liste = bl ? JSON.parse(bl) : [];
  liste.unshift({ id, etab, tel, refPaie, montant: f.prix,
                  formule: f.titre, date: new Date().toISOString() });
  await env.SALONS.put('v:attente', JSON.stringify(liste.slice(0, 500)));
  return json(200, { ok: true, ref: id });
}

/* Le vendeur confirme avoir vu l'argent arriver : la licence est émise. */
async function valider(url, req, env) {
  const attendu = await motDePasseAdmin(env);
  if (!attendu || url.searchParams.get('k') !== attendu)
    return json(401, { erreur: 'Accès refusé.' });
  const b = await req.json();
  const id = String(b.id || '');
  const refuser = !!b.refuser;

  const bl = await env.SALONS.get('v:attente');
  const liste = (bl ? JSON.parse(bl) : []).filter(x => x.id !== id);
  await env.SALONS.put('v:attente', JSON.stringify(liste));

  if (refuser) {
    await env.SALONS.put('v:refus:' + id, '1', { expirationTtl: 86400 * 30 });
    return json(200, { ok: true, refuse: true });
  }
  if (!selUtilisable(env))
    return json(503, { erreur: "Le secret LIC_SEL est absent ou incorrect dans Cloudflare : "
                             + "aucune licence ne peut être émise. Corrigez-le puis revalidez." });
  const v = await emettre(env, id);
  if (!v) return json(404, { erreur: 'Commande introuvable ou déjà traitée.' });
  return json(200, { ok: true, cle: v.cle, exp: v.exp });
}

/* La page « merci » interroge ceci. Relance la vérification si le webhook
   a pris du retard — le client n'attend donc jamais après CinetPay. */
async function laCle(url, env) {
  const id = url.searchParams.get('ref') || '';
  if (!id) return json(400, { erreur: 'Référence manquante.' });
  let v = await env.SALONS.get('v:paye:' + id);
  if (v) return json(200, JSON.parse(v));
  const livree = await livrer(env, id);
  if (livree) return json(200, livree);
  return json(202, { attente: true });
}

/* Filet de sécurité client : retrouver sa clé avec son numéro. */
async function mesCles(url, env) {
  const tel = nettoyerTel(url.searchParams.get('tel'));
  if (tel.length < 8) return json(400, { erreur: 'Numéro invalide.' });
  const v = await env.SALONS.get('v:tel:' + tel);
  if (!v) return json(404, { erreur: 'Aucune licence trouvée pour ce numéro.' });
  return json(200, JSON.parse(v));
}

/* Espace de parrainage : son code, ses filleuls, et sa clé prolongée. */
async function parrainage(url, env) {
  const tel = nettoyerTel(url.searchParams.get('tel'));
  if (tel.length < 8) return json(400, { erreur: 'Numéro invalide.' });
  const brut = await env.SALONS.get('v:tel:' + tel);
  if (!brut) return json(404, { erreur: "Aucune licence à ce numéro. Le parrainage est réservé aux clients." });
  const v = JSON.parse(brut);
  const code = await attribuerCode(env, tel);
  const bl = await env.SALONS.get('v:filleuls:' + tel);
  const filleuls = bl ? JSON.parse(bl) : [];
  return json(200, {
    code, etab: v.etab, cle: v.cle, exp: v.exp,
    filleuls: filleuls.length,
    moisGagnes: filleuls.reduce((s, f) => s + (f.mois || 0), 0),
    detail: filleuls.slice(0, 20).map(f => ({ etab: f.etab, date: (f.date || '').slice(0, 10) }))
  });
}
/* Vérifie un code avant l'achat, pour rassurer l'acheteur. */
async function verifierCode(url, env) {
  const code = String(url.searchParams.get('code') || '').trim().toUpperCase();
  const t = await env.SALONS.get('v:parr:' + code);
  if (!t) return json(404, { valide: false });
  return json(200, { valide: true, bonus: BONUS_FILLEUL });
}

/* ------------------------------------------------------------------ */
/*  Tableau de bord privé                                              */
/* ------------------------------------------------------------------ */
/* Mot de passe du tableau de bord. Le secret Cloudflare prime s'il existe ;
   sinon on lit celui que le vendeur a choisi lui-même, rangé dans le KV.
   Cela évite de dépendre d'un réglage de tableau de bord tiers. */
async function motDePasseAdmin(env) {
  if (env.ADMIN_CLE) return String(env.ADMIN_CLE).trim();
  return await env.SALONS.get('v:admincle');
}

/* Écran commun : première mise en place, ou simple demande du mot de passe. */
function pageAcces(premiere, message) {
  return html(premiere ? 200 : 401, `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jaraba — tableau de bord</title><style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
background:#E8E9EC;color:#1B1C1E;display:flex;align-items:center;justify-content:center;
min-height:100dvh;padding:22px}
.b{background:#fff;border-radius:26px;padding:28px 24px;max-width:420px;width:100%;
box-shadow:0 12px 40px rgba(5,29,56,.12)}
h1{font-size:23px;font-weight:800;margin:0 0 6px;letter-spacing:-.4px}
p{color:#7A7D84;font-size:15px;margin:0 0 18px;line-height:1.55}
label{display:block;font-size:11.5px;font-weight:700;color:#7A7D84;text-transform:uppercase;
letter-spacing:.5px;margin-bottom:6px}
input{width:100%;padding:15px 17px;border:none;border-radius:15px;font-size:16.5px;
font-family:inherit;background:#E8E9EC;color:#1B1C1E;margin-bottom:14px;box-sizing:border-box}
input:focus{outline:2px solid #C99948}
button{width:100%;border:none;border-radius:999px;padding:15px;font-size:16px;font-weight:700;
font-family:inherit;cursor:pointer;background:#C99948;color:#241905;min-height:52px}
.av{background:#F5EDDE;color:#8E6B2F;border-radius:14px;padding:13px 15px;font-size:14px;
font-weight:600;margin-bottom:16px;line-height:1.5}
.ko{background:#FAE8E5;color:#7C241A;border-radius:14px;padding:13px 15px;font-size:14.5px;
font-weight:600;margin-bottom:16px}
</style></head><body><div class="b">
${message ? '<div class="ko">' + esc(message) + '</div>' : ''}
${premiere ? `<h1>Protégez votre tableau de bord</h1>
  <p>Personne n'a encore choisi de mot de passe. Choisissez-en un maintenant : il sera
     demandé à chaque accès, et vous seul pourrez le changer ensuite.</p>
  <div class="av">Faites-le tout de suite : tant que ce mot de passe n'est pas posé,
     quiconque connaît cette adresse pourrait le choisir à votre place.</div>
  <form method="POST" action="/vente/admin-cle">
    <label for="n">Mot de passe</label>
    <input type="text" id="n" name="nouveau" placeholder="au moins 6 caractères" autofocus>
    <button type="submit">Enregistrer</button>
  </form>`
: `<h1>Tableau de bord</h1>
  <p>Entrez le mot de passe que vous avez choisi.</p>
  <form method="GET" action="/vente/admin">
    <label for="k">Mot de passe</label>
    <input type="password" id="k" name="k" autofocus>
    <button type="submit">Ouvrir</button>
  </form>`}
</div></body></html>`);
}

/* Pose le mot de passe la première fois, ou le remplace si l'ancien est fourni. */
async function definirClehAdmin(req, env) {
  if (env.ADMIN_CLE)
    return html(400, '<meta charset="utf-8"><p style="font-family:sans-serif">'
      + 'Le mot de passe est fixé par le secret ADMIN_CLE dans Cloudflare : '
      + 'retirez-le pour pouvoir le choisir ici.</p>');
  let d = {};
  try {
    const ct = req.headers.get('content-type') || '';
    if (ct.includes('json')) d = await req.json();
    else { const f = await req.formData(); d = { nouveau: f.get('nouveau'), actuel: f.get('actuel') }; }
  } catch (e) { /* corps illisible */ }

  const nouveau = String(d.nouveau || '').trim();
  if (nouveau.length < 6) return pageAcces(true, 'Choisissez au moins six caractères.');

  const existant = await env.SALONS.get('v:admincle');
  if (existant && String(d.actuel || '').trim() !== existant)
    return pageAcces(false, 'Un mot de passe est déjà en place. Entrez-le pour le remplacer.');

  await env.SALONS.put('v:admincle', nouveau);
  return new Response(null, { status: 303,
    headers: { Location: '/vente/admin?k=' + encodeURIComponent(nouveau) } });
}

async function admin(url, env) {
  const attendu = await motDePasseAdmin(env);
  if (!attendu) return pageAcces(true, '');
  if (url.searchParams.get('k') !== attendu) return pageAcces(false, '');

  const brut = await env.SALONS.get('v:index');
  const liste = brut ? JSON.parse(brut) : [];
  const ba = await env.SALONS.get('v:attente');
  const attente = ba ? JSON.parse(ba) : [];
  const moisCourant = new Date().toISOString().slice(0, 7);
  const payantes = liste.filter(v => v.montant > 0);
  const caTotal = payantes.reduce((s, v) => s + v.montant, 0);
  const caMois = payantes.filter(v => (v.date || '').slice(0, 7) === moisCourant)
                         .reduce((s, v) => s + v.montant, 0);
  const bientot = liste.filter(v => v.exp && v.exp <= moisCourant);

  const lignes = liste.slice(0, 300).map(v => '<tr>'
    + '<td>' + esc((v.date || '').slice(0, 10)) + '</td>'
    + '<td><b>' + esc(v.etab) + '</b></td>'
    + '<td>' + esc(v.tel) + '</td>'
    + '<td>' + esc(v.formule) + '</td>'
    + '<td class="n">' + (v.montant ? fmtF(v.montant) : '—') + '</td>'
    + '<td>' + esc(v.exp) + '</td></tr>').join('');

  return html(200, `<!DOCTYPE html><html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Jaraba — ventes</title><style>
body{margin:0;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Arial,sans-serif;
background:#E8E9EC;color:#1B1C1E;padding:18px}
h1{font-size:24px;font-weight:800;margin:0 0 14px}
.k{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin-bottom:16px}
.c{background:#fff;border-radius:18px;padding:15px;box-shadow:0 1px 3px rgba(27,28,30,.06)}
.c .v{font-size:24px;font-weight:800;letter-spacing:-.5px}
.c .l{font-size:11px;color:#84878D;font-weight:600;text-transform:uppercase;letter-spacing:.4px;margin-top:3px}
table{width:100%;border-collapse:collapse;background:#fff;border-radius:18px;overflow:hidden;
box-shadow:0 1px 3px rgba(27,28,30,.06);font-size:13.5px}
th{background:#051D38;color:#fff;text-align:left;padding:11px;font-size:11px;
text-transform:uppercase;letter-spacing:.4px}
td{padding:11px;border-bottom:1px solid #F0F1F3}
td.n{text-align:right;font-variant-numeric:tabular-nums;font-weight:700}
.warn{background:#F5EDDE;color:#8E6B2F;border-radius:14px;padding:12px 14px;font-size:13.5px;
font-weight:600;margin-bottom:14px}
h2.st{font-size:17px;font-weight:800;margin:26px 0 6px;display:flex;align-items:center;gap:9px}
.pill{background:#C99948;color:#241905;border-radius:999px;padding:2px 10px;font-size:12.5px}
.aide{font-size:13.5px;color:#84878D;margin:0 0 12px}
.att{background:#fff;border-radius:18px;padding:15px;margin-bottom:10px;
box-shadow:0 1px 3px rgba(27,28,30,.06);border-left:4px solid #C99948}
.att .hd{display:flex;justify-content:space-between;align-items:baseline;gap:10px}
.att .hd b{font-size:16.5px}
.att .mt{font-size:18px;font-weight:800;font-variant-numeric:tabular-nums;white-space:nowrap}
.att .mn{font-size:13px;color:#84878D;margin-top:3px}
.att .rf{font-size:14px;margin-top:9px;background:#F2F3F5;border-radius:12px;padding:9px 12px;
word-break:break-all}
.att .ac{display:flex;gap:9px;margin-top:12px}
.att button{flex:1;border:none;border-radius:999px;padding:12px;font-size:14.5px;font-weight:700;
font-family:inherit;cursor:pointer;min-height:46px}
.att .ok{background:#051D38;color:#fff}
.att .no{background:#F2F3F5;color:#C0392B}
.fait{background:#E6F4EC;color:#14512C;border-radius:16px;padding:14px;font-size:14.5px;
font-weight:600;margin-bottom:10px}
</style></head><body>
<h1>Ventes Jaraba</h1>
<div class="k">
  <div class="c"><div class="v">${fmtF(caMois)}</div><div class="l">Ce mois-ci</div></div>
  <div class="c"><div class="v">${fmtF(caTotal)}</div><div class="l">Depuis le début</div></div>
  <div class="c"><div class="v">${payantes.length}</div><div class="l">Licences vendues</div></div>
  <div class="c"><div class="v">${liste.length - payantes.length}</div><div class="l">Essais</div></div>
</div>
${bientot.length ? '<div class="warn">' + bientot.length
  + ' licence(s) arrivent à échéance ce mois-ci — c\'est le moment de relancer.</div>' : ''}

${attente.length ? `<h2 class="st">Paiements à confirmer <span class="pill">${attente.length}</span></h2>
<p class="aide">Vérifiez que la somme est bien arrivée sur votre Mobile Money, puis confirmez :
la clé part alors toute seule chez le client, qui la voit apparaître sur sa page.</p>
${attente.map(a => `<div class="att" id="a-${esc(a.id)}">
  <div class="hd"><b>${esc(a.etab)}</b><span class="mt">${fmtF(a.montant)}</span></div>
  <div class="mn">${esc(a.formule)} · ${esc(a.tel)} · ${esc((a.date || '').slice(0, 10))}</div>
  <div class="rf">Référence donnée : <b>${esc(a.refPaie)}</b></div>
  <div class="ac">
    <button class="ok" onclick="tranche('${esc(a.id)}',false)">J'ai reçu l'argent</button>
    <button class="no" onclick="tranche('${esc(a.id)}',true)">Refuser</button>
  </div></div>`).join('')}` : ''}

<h2 class="st">Historique</h2>
<table><tr><th>Date</th><th>Établissement</th><th>Téléphone</th><th>Formule</th>
<th style="text-align:right">Montant</th><th>Fin</th></tr>${lignes}</table>
<script>
var CLE = new URLSearchParams(location.search).get('k');
function tranche(id, refus){
  if(refus && !confirm('Refuser cette demande ?')) return;
  var bloc = document.getElementById('a-' + id);
  bloc.style.opacity = '.5';
  fetch('/vente/valider?k=' + encodeURIComponent(CLE), {
    method:'POST', headers:{'Content-Type':'application/json'},
    body: JSON.stringify({id:id, refuser:refus})
  }).then(function(r){ return r.json(); }).then(function(j){
    if(j.ok){ bloc.outerHTML = '<div class="fait">' + (refus ? 'Refusé.'
      : 'Licence délivrée jusqu\\'à fin ' + j.exp + ' — le client la reçoit à l\\'instant.') + '</div>'; }
    else { bloc.style.opacity = '1'; alert(j.erreur || 'Impossible.'); }
  }).catch(function(){ bloc.style.opacity = '1'; alert('Pas de réseau.'); });
}
</script>
</body></html>`);
}

/* ------------------------------------------------------------------ */
/*  Routage                                                            */
/* ------------------------------------------------------------------ */
export default {
  async fetch(req, env) {
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors() });
    const u = new URL(req.url);
    const chemin = u.pathname.replace(/\/+$/, '') || '/';

    try {
      /* ---------------- tunnel de vente ---------------- */
      if (chemin === '/vente/tarifs' && req.method === 'GET')
        return json(200, {
          devise: DEVISE, formules: FORMULES,
          /* « auto » dès qu'un encaisseur est configuré, « direct » sinon */
          paiement: (env.CINETPAY_KEY && env.CINETPAY_SITE) ? 'auto' : 'direct',
          momo: env.MOMO_NUMERO || MOMO_DEFAUT.numero,
          momoNom: env.MOMO_NOM || MOMO_DEFAUT.nom
        });
      if (chemin === '/vente/declarer' && req.method === 'POST') return declarer(req, env);
      if (chemin === '/vente/valider'  && req.method === 'POST') return valider(u, req, env);
      if (chemin === '/vente/essai'  && req.method === 'POST') return essai(req, env);
      if (chemin === '/vente/acheter'&& req.method === 'POST') return acheter(req, env, u.origin);
      if (chemin === '/vente/notify' && req.method === 'POST') return notify(req, env);
      if (chemin === '/vente/cle'    && req.method === 'GET')  return laCle(u, env);
      if (chemin === '/vente/mes-cles' && req.method === 'GET') return mesCles(u, env);
      if (chemin === '/vente/parrainage' && req.method === 'GET') return parrainage(u, env);
      if (chemin === '/vente/code' && req.method === 'GET') return verifierCode(u, env);
      if (chemin === '/vente/admin'  && req.method === 'GET')  return admin(u, env);
      if (chemin === '/vente/admin-cle' && req.method === 'POST') return definirClehAdmin(req, env);
      /* Contrôle de configuration : dit en clair ce qui manque, sans exposer
         aucun secret. Accessible sans mot de passe, car il ne révèle rien. */
      if (chemin === '/vente/verif' && req.method === 'GET') {
        const sel = selUtilisable(env);
        const mdp = await motDePasseAdmin(env);
        return json(200, {
          licences: sel ? 'ok' : 'LIC_SEL incorrect — retirez ce secret pour revenir au sel intégré',
          tableauDeBord: mdp ? 'protégé' : 'mot de passe à choisir sur /vente/admin',
          encaissement: (env.CINETPAY_KEY && env.CINETPAY_SITE) ? 'automatique' : 'direct',
          stockage: env.SALONS ? 'ok' : 'binding SALONS absent',
          venteOperationnelle: !!(sel && env.SALONS),
          pret: !!(sel && env.SALONS)
        });
      }

      /* ---------------- serveur de liaison ------------- */
      if (chemin === '/' || chemin === '/sante')
        return json(200, { ok: true, service: 'liaison', salons: env.SALON ? 'durables' : 'absent' });

      /* Chaque bar a son objet, désigné par l'empreinte de son salon. Le
         Worker contrôle la clé ; l'objet fait le travail. Il ne reçoit donc
         jamais une requête qu'il aurait dû refuser. */
      const versSalon = (salon, route, methode, corps) => {
        if (!env.SALON)
          return json(503, { erreur: 'liaison indisponible : le binding SALON manque dans wrangler.toml' });
        const stub = env.SALON.get(env.SALON.idFromName(String(salon)));
        return stub.fetch(new Request('https://salon.jaraba' + route, {
          method: methode,
          headers: { 'Content-Type': 'application/json' },
          body: methode === 'POST' ? JSON.stringify(corps || {}) : undefined
        }));
      };
      const refus = () => json(403, { erreur: 'clé du salon absente ou incorrecte' });

      /* La ligne ouverte : le poste du gérant s'y branche une fois pour la
         soirée, et les commandes lui arrivent au lieu d'être réclamées. */
      if (chemin === '/flux') {
        const s = u.searchParams.get('s'), k = u.searchParams.get('k');
        if (!salonAutorise(s, k)) return refus();
        if (!env.SALON) return json(503, { erreur: 'liaison indisponible' });
        if (req.headers.get('Upgrade') !== 'websocket')
          return json(426, { erreur: 'cette adresse attend une connexion WebSocket' });
        const stub = env.SALON.get(env.SALON.idFromName(String(s)));
        return stub.fetch(new Request('https://salon.jaraba/flux', {
          headers: { Upgrade: 'websocket' }
        }));
      }

      if (chemin === '/menu' && req.method === 'POST') {
        const b = await req.json();
        if (!b.s || !b.menu) return json(400, { erreur: 'salon ou carte manquant' });
        /* Publier une carte engage l'image du bar : réservé à qui détient la clé. */
        if (!salonAutorise(b.s, b.k)) return refus();
        return versSalon(b.s, '/menu', 'POST', { menu: b.menu, photos: b.photos });
      }
      if (chemin === '/menu' && req.method === 'GET') {
        return versSalon(u.searchParams.get('s'), '/menu', 'GET');
      }
      if (chemin === '/photos' && req.method === 'GET') {
        return versSalon(u.searchParams.get('s'), '/photos', 'GET');
      }
      if (chemin === '/commande' && req.method === 'POST') {
        const b = await req.json();
        if (!b.s || !Array.isArray(b.items) || !b.items.length)
          return json(400, { erreur: 'commande vide' });
        /* Volontairement ouvert : c'est le client attablé qui commande, et il
           n'a que le QR. L'objet du bar range la commande sans risque de perte. */
        return versSalon(b.s, '/commande', 'POST', { table: b.table, items: b.items });
      }
      if (chemin === '/commandes' && req.method === 'GET') {
        /* La file dit qui consomme quoi, table par table : elle n'a rien à
           faire entre les mains d'un client. Cette route reste le filet de
           secours des appareils qui ne tiennent pas de ligne ouverte. */
        const s = u.searchParams.get('s');
        if (!salonAutorise(s, u.searchParams.get('k'))) return refus();
        const depuis = Number(u.searchParams.get('depuis')) || 0;
        return versSalon(s, '/commandes?depuis=' + depuis, 'GET');
      }
      /* Le coffre : une sauvegarde chiffrée sur l'appareil, rangée sous un nom
         dérivé du code de récupération. Le relais ne sait ni la lire, ni dire
         à quel bar elle appartient. */
      if (chemin === '/coffre' && req.method === 'POST') {
        const b = await req.json();
        if (!b.n || !b.t || !b.d) return json(400, { erreur: 'sauvegarde incomplète' });
        if (String(b.d).length > 4000000) return json(413, { erreur: 'sauvegarde trop volumineuse' });
        return versSalon(b.n, '/coffre', 'POST', { t: b.t, d: b.d, v: b.v });
      }
      if (chemin === '/coffre' && req.method === 'GET') {
        const n = u.searchParams.get('n');
        if (!n) return json(400, { erreur: 'adresse de coffre manquante' });
        return versSalon(n, '/coffre', 'GET');
      }

      if (chemin === '/pris' && req.method === 'POST') {
        const b = await req.json();
        /* Marquer une commande « prise » la fait disparaître de l'écran du
           serveur : un tiers ne doit jamais pouvoir escamoter une commande. */
        if (!salonAutorise(b.s, b.k)) return refus();
        return versSalon(b.s, '/pris', 'POST', { id: b.id });
      }

      return json(404, { erreur: 'route inconnue' });
    } catch (e) {
      return json(400, { erreur: String((e && e.message) || e) });
    }
  }
};

/* =========================================================================
   SALON DURABLE — un objet par bar

   Le stockage clé-valeur de Cloudflare est réparti sur toute la planète : deux
   commandes envoyées à la même seconde lisent la même file, y ajoutent chacune
   la sienne, et la réécrivent — la seconde écrase la première. Le client a vu
   « votre commande est partie », le serveur ne la verra jamais.

   Un Durable Object règle cela par construction : il n'existe qu'un seul objet
   par bar, en un seul endroit, et il traite ses requêtes l'une après l'autre.
   Lire-modifier-écrire y est sûr sans verrou, parce qu'il n'y a personne
   d'autre dans la pièce.

   Il apporte deux choses de plus, qui comptent autant :

   — la ligne ouverte. Le poste du gérant se connecte une fois et reste
     connecté ; quand une table commande, l'objet lui pousse la commande. On
     passe de quinze secondes d'attente à une demi-seconde, et de 5 760
     interrogations par jour à une poignée de messages.

   — le sommeil. Entre deux commandes, Cloudflare met l'objet en hibernation :
     la connexion survit, mais plus rien n'est facturé. Les « ping » de
     maintien reçoivent même une réponse automatique sans réveiller l'objet.
   ========================================================================= */

const RETENTION_MS = 3 * 3600 * 1000;        /* les commandes s'oublient après 3 h */
const OUBLI_MS = 30 * 24 * 3600 * 1000;      /* un bar sans activité s'efface après 30 j */
const OUBLI_COFFRE_MS = 365 * 24 * 3600 * 1000;  /* une sauvegarde, elle, se garde un an */

export class SalonDurable {
  constructor(ctx, env) {
    this.ctx = ctx;
    this.env = env;

    /* Les « ping » de maintien de connexion reçoivent « pong » sans réveiller
       l'objet : c'est ce qui rend une ligne ouverte réellement gratuite. */
    try {
      this.ctx.setWebSocketAutoResponse(
        new WebSocketRequestResponsePair('ping', 'pong'));
    } catch (e) { /* environnement sans réponse automatique : sans conséquence */ }
  }

  /* ------------------------------------------------------------------ */
  /*  Petits utilitaires de stockage                                     */
  /* ------------------------------------------------------------------ */

  async lire(cle, defaut) {
    const v = await this.ctx.storage.get(cle);
    return v === undefined || v === null ? defaut : v;
  }

  /* Toute écriture repousse la date d'oubli : un bar actif ne s'efface pas. */
  async ecrire(cle, valeur) {
    await this.ctx.storage.put(cle, valeur);
    try { await this.ctx.storage.setAlarm(Date.now() + OUBLI_MS); } catch (e) {}
  }

  /* Cloudflare appelle ceci quand l'échéance arrive sans nouvelle écriture. */
  /* L'échéance d'oubli. Un coffre déposé récemment survit à l'effacement du
     reste : perdre la sauvegarde d'un gérant parti trois mois serait bête. */
  async alarm() {
    const coffre = await this.lire('coffre', null);
    if (coffre && Date.now() - coffre.t < OUBLI_COFFRE_MS) {
      await this.ctx.storage.delete('menu');
      await this.ctx.storage.delete('photos');
      await this.ctx.storage.delete('cmds');
      try { await this.ctx.storage.setAlarm(coffre.t + OUBLI_COFFRE_MS); } catch (e) {}
      return;
    }
    await this.ctx.storage.deleteAll();
  }

  diffuser(message) {
    const texte = JSON.stringify(message);
    let sockets = [];
    try { sockets = this.ctx.getWebSockets(); } catch (e) { return 0; }
    let envoyes = 0;
    for (const ws of sockets) {
      try { ws.send(texte); envoyes++; }
      catch (e) { /* une ligne coupée se nettoie toute seule */ }
    }
    return envoyes;
  }

  /* La file, débarrassée des commandes prises et des trop anciennes. */
  async fileVivante() {
    const limite = Date.now() - RETENTION_MS;
    const brut = await this.lire('cmds', []);
    const vivantes = brut.filter(c => !c.pris && c.ts > limite);
    if (vivantes.length !== brut.length) await this.ctx.storage.put('cmds', vivantes);
    return vivantes;
  }

  /* ------------------------------------------------------------------ */
  /*  Les requêtes, transmises par le Worker après contrôle de la clé    */
  /* ------------------------------------------------------------------ */

  async fetch(requete) {
    const u = new URL(requete.url);
    const chemin = u.pathname.replace(/\/+$/, '') || '/';

    /* ---- la ligne ouverte ---- */
    if (chemin === '/flux') {
      if (requete.headers.get('Upgrade') !== 'websocket')
        return new Response('websocket attendu', { status: 426 });

      const paire = new WebSocketPair();
      const client = paire[0], serveur = paire[1];
      this.ctx.acceptWebSocket(serveur);

      /* On envoie l'état courant à l'ouverture : un poste qui vient de se
         reconnecter ne doit pas rater les commandes arrivées entre-temps. */
      const file = await this.fileVivante();
      try { serveur.send(JSON.stringify({ t: 'file', list: file, ts: Date.now() })); }
      catch (e) {}

      return new Response(null, { status: 101, webSocket: client });
    }

    const corps = requete.method === 'POST' ? await requete.json().catch(() => ({})) : {};

    /* ---- la carte ---- */
    if (chemin === '/menu' && requete.method === 'POST') {
      await this.ecrire('menu', corps.menu);
      const n = corps.photos ? Object.keys(corps.photos).length : 0;
      if (n) await this.ecrire('photos', corps.photos);
      else await this.ctx.storage.delete('photos');
      /* La carte a changé : les postes ouverts le savent immédiatement. */
      this.diffuser({ t: 'carte', ts: Date.now() });
      return this.reponse(200, { ok: true, photos: n });
    }

    if (chemin === '/menu' && requete.method === 'GET') {
      const menu = await this.lire('menu', null);
      if (!menu) return this.reponse(404, { erreur: 'carte introuvable' });
      return this.reponse(200, { menu });
    }

    if (chemin === '/photos') {
      /* Plusieurs centaines de kilo-octets qui ne changent presque jamais :
         cinq minutes de cache épargnent la data des clients. */
      return this.reponse(200, { photos: await this.lire('photos', {}) },
        'public, max-age=300');
    }

    /* ---- les commandes ---- */
    if (chemin === '/commande' && requete.method === 'POST') {
      if (!Array.isArray(corps.items) || !corps.items.length)
        return this.reponse(400, { erreur: 'commande vide' });

      /* Lire, ajouter, écrire — sans risque : l'objet ne traite qu'une
         requête à la fois. C'est tout l'intérêt de l'avoir amené ici. */
      const list = await this.lire('cmds', []);
      const c = {
        id: 'C' + Date.now().toString(36) + Math.random().toString(36).slice(2, 5),
        table: String(corps.table || '').slice(0, 40),
        items: corps.items.slice(0, 60),
        ts: Date.now(), pris: false
      };
      list.push(c);
      await this.ecrire('cmds', list.slice(-200));

      const postes = this.diffuser({ t: 'commande', c });
      return this.reponse(200, { ok: true, id: c.id, postes });
    }

    /* ---- le coffre ---- */
    if (chemin === '/coffre' && requete.method === 'POST') {
      /* Le jeton est lui aussi dérivé du code : celui qui a trouvé l'adresse
         sans avoir le code ne peut pas écraser la sauvegarde d'un autre. */
      const connu = await this.lire('jeton', null);
      if (connu && connu !== corps.t)
        return this.reponse(403, { erreur: 'jeton de coffre incorrect' });
      if (!connu) await this.ctx.storage.put('jeton', corps.t);

      await this.ctx.storage.put('coffre', { d: corps.d, v: corps.v || 1, t: Date.now() });
      /* Une sauvegarde se garde un an sans nouvelle, pas trente jours. */
      try { await this.ctx.storage.setAlarm(Date.now() + OUBLI_COFFRE_MS); } catch (e) {}
      return this.reponse(200, {
        ok: true, premiere: !connu, taille: String(corps.d).length
      });
    }
    if (chemin === '/coffre' && requete.method === 'GET') {
      const c = await this.lire('coffre', null);
      if (!c) return this.reponse(404, { erreur: 'aucune sauvegarde à cette adresse' });
      return this.reponse(200, { d: c.d, v: c.v, t: c.t });
    }

    if (chemin === '/commandes' && requete.method === 'GET') {
      const depuis = Number(u.searchParams.get('depuis')) || 0;
      const file = await this.fileVivante();
      return this.reponse(200, { t: Date.now(), list: file.filter(c => c.ts > depuis) });
    }

    if (chemin === '/pris' && requete.method === 'POST') {
      const list = await this.lire('cmds', []);
      let trouve = false;
      const maj = list.map(c => {
        if (c.id !== corps.id) return c;
        trouve = true;
        return { ...c, pris: true };
      });
      if (trouve) {
        await this.ecrire('cmds', maj);
        /* Un autre poste du même bar a peut-être la commande à l'écran :
           elle doit y disparaître aussi, sans quoi elle serait servie deux fois. */
        this.diffuser({ t: 'pris', id: corps.id });
      }
      return this.reponse(200, { ok: true, trouve });
    }

    return this.reponse(404, { erreur: 'route inconnue dans le salon' });
  }

  reponse(code, obj, cache) {
    return new Response(JSON.stringify(obj), {
      status: code,
      headers: {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET,POST,OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type',
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': cache || 'no-store, max-age=0'
      }
    });
  }

  /* ------------------------------------------------------------------ */
  /*  Réveils depuis une ligne ouverte                                   */
  /* ------------------------------------------------------------------ */

  /* Le poste n'a presque rien à dire : les « ping » sont déjà traités sans
     réveil. Reste la reprise après une coupure réseau. */
  async webSocketMessage(ws, message) {
    let m;
    try { m = JSON.parse(String(message)); } catch (e) { return; }
    if (m && m.t === 'rattraper') {
      const file = await this.fileVivante();
      try { ws.send(JSON.stringify({ t: 'file', list: file, ts: Date.now() })); } catch (e) {}
    }
  }

  async webSocketClose(ws) { try { ws.close(); } catch (e) {} }
  async webSocketError(ws) { try { ws.close(); } catch (e) {} }
}
