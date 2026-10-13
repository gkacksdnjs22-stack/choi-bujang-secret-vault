import {traceRequest} from '../src/request-trace.mjs';
import { runRuleCheck } from '../src/rule-check.mjs';

export default async function handler(req,res) {
  res.setHeader('Content-Type','application/json; charset=utf-8');
  traceRequest(res);
  res.setHeader('Cache-Control','no-store');
  if (req.method !== 'GET') return res.status(405).json({error:'read_only_check'});
  const query = req.query ?? {};
  if (Object.keys(query).some(key=>key!=='case') || typeof query.case !== 'string') {
    return res.status(400).json({error:'unknown_check'});
  }
  const result = await runRuleCheck(query.case);
  return result ? res.status(200).json(result) : res.status(400).json({error:'unknown_check'});
}
