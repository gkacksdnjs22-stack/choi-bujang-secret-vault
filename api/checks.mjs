import {traceRequest} from '../src/request-trace.mjs';
import { runRuleCheck } from '../src/rule-check.mjs';
import {readFile} from 'node:fs/promises';
import {summarizeChecks} from '../src/check-summary.mjs';

export default async function handler(req,res) {
  res.setHeader('Content-Type','application/json; charset=utf-8');
  traceRequest(res);
  res.setHeader('Cache-Control','no-store');
  if (req.method !== 'GET') return res.status(405).json({error:'read_only_check'});
  const query = req.query ?? {};
  if(Object.keys(query).length===0){
    try{
      const receipt=JSON.parse(await readFile(new URL('../artifacts/checks.json',import.meta.url),'utf8'));
      return res.status(200).json(summarizeChecks(receipt));
    }catch{return res.status(503).json({error:'checks_unavailable'});}
  }
  if (Object.keys(query).some(key=>key!=='case') || typeof query.case !== 'string') {
    return res.status(400).json({error:'unknown_check'});
  }
  const result = await runRuleCheck(query.case);
  return result ? res.status(200).json(result) : res.status(400).json({error:'unknown_check'});
}
