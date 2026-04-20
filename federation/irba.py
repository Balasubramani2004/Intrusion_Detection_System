"""FedAIDA-IDS: IRBA Trust Scoring (Novelty N4)"""
import os, sys, logging, json
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import numpy as np
from collections import defaultdict
logger = logging.getLogger(__name__)

try:
    from config import (IRBA_COSINE_WEIGHT,IRBA_COVERAGE_WEIGHT,IRBA_HISTORY_WEIGHT,
                        IRBA_QUARANTINE_THRESH,IRBA_NEW_NODE_TRUST,IRBA_MAX_TRUST,NUM_CLASSES)
except:
    IRBA_COSINE_WEIGHT=0.4;IRBA_COVERAGE_WEIGHT=0.4;IRBA_HISTORY_WEIGHT=0.2
    IRBA_QUARANTINE_THRESH=0.20;IRBA_NEW_NODE_TRUST=0.50;IRBA_MAX_TRUST=0.95;NUM_CLASSES=5


class IRBATrustScorer:
    """IDS-Aware Reputation-Based Aggregation. Three-signal trust scoring."""
    def __init__(self, n_nodes, n_classes=NUM_CLASSES):
        self.n_nodes=n_nodes; self.n_classes=n_classes
        self.trust_scores={i:IRBA_NEW_NODE_TRUST for i in range(n_nodes)}
        self.quarantined=set()
        self.round_history=defaultdict(list)
        self.coverage_scores={i:0.5 for i in range(n_nodes)}
        self.trust_log=[]

    def _cosine_sim(self, u, m):
        u=u.flatten().astype(np.float64); m=m.flatten().astype(np.float64)
        nu=np.linalg.norm(u); nm=np.linalg.norm(m)
        if nu<1e-10 or nm<1e-10: return 0.5
        return float(np.clip((np.dot(u,m)/(nu*nm)+1.0)/2.0, 0.0, 1.0))

    def update_coverage(self, node_id, model_eval_fn, val_X, val_y):
        try:
            preds=model_eval_fn(val_X)
            detected=sum(1 for c in range(self.n_classes)
                         if len(np.where(val_y==c)[0])>0 and
                            np.mean(preds[np.where(val_y==c)[0]]==c)>=0.5)
            cov=detected/self.n_classes
            self.coverage_scores[node_id]=cov; return cov
        except Exception as e:
            logger.warning(f"Coverage eval node {node_id}: {e}")
            return self.coverage_scores.get(node_id,0.5)

    def _historical_score(self, node_id):
        h=self.round_history[node_id]
        if len(h)<3: return IRBA_NEW_NODE_TRUST
        var=np.var(h[-5:])
        return float(np.clip(1.0-min(var*4,1.0), 0.0, 1.0))

    def update_trust(self, node_id, weight_update, all_updates, coverage_score=None):
        if node_id in self.quarantined: return 0.0
        flat_upds=[v.flatten() for v in all_updates.values() if v is not None]
        if not flat_upds: return self.trust_scores[node_id]
        min_len=min(len(u) for u in flat_upds)
        median_upd=np.median([u[:min_len] for u in flat_upds],axis=0)
        s1=self._cosine_sim(weight_update.flatten()[:min_len], median_upd)
        s2=coverage_score if coverage_score is not None else self.coverage_scores.get(node_id,0.5)
        s3=self._historical_score(node_id)
        trust=float(np.clip(IRBA_COSINE_WEIGHT*s1+IRBA_COVERAGE_WEIGHT*s2+IRBA_HISTORY_WEIGHT*s3, 0.0, IRBA_MAX_TRUST))
        self.trust_scores[node_id]=0.7*self.trust_scores[node_id]+0.3*trust
        self.round_history[node_id].append(self.trust_scores[node_id])
        if self.trust_scores[node_id]<IRBA_QUARANTINE_THRESH:
            self.quarantined.add(node_id)
            logger.warning(f"NODE {node_id} QUARANTINED (trust={self.trust_scores[node_id]:.3f})")
        return self.trust_scores[node_id]

    def aggregate(self, all_weights, n_samples):
        active={nid:w for nid,w in all_weights.items() if nid not in self.quarantined and w}
        if not active: return None
        total=sum(self.trust_scores[n]*n_samples.get(n,1) for n in active)
        agg=None
        for nid,weights in active.items():
            wt=self.trust_scores[nid]*n_samples.get(nid,1)/(total+1e-8)
            agg=[a+p*wt for a,p in zip(agg,weights)] if agg else [p*wt for p in weights]
        self.trust_log.append({"trust_scores":{k:round(v,4) for k,v in self.trust_scores.items()},
                                "quarantined":list(self.quarantined)})
        return agg

    def get_status(self):
        return {"trust_scores":{k:round(v,4) for k,v in self.trust_scores.items()},
                "quarantined":list(self.quarantined),
                "active_nodes":[i for i in range(self.n_nodes) if i not in self.quarantined]}

    def save_log(self, path):
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        with open(path,"w") as f: json.dump(self.trust_log, f, indent=2)
