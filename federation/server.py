# ============================================================
# federation/server.py
# Flower FL Server with IRBA Trust-Weighted Aggregation
# NOVELTY 4: IDS-aware Byzantine poisoning defence
# ============================================================

import flwr as fl
from flwr.common import (
    FitRes, Parameters, Scalar, ndarrays_to_parameters,
    parameters_to_ndarrays
)
from flwr.server.strategy import Strategy
from flwr.server.client_proxy import ClientProxy
import numpy as np
from typing import Dict, List, Optional, Tuple, Union
import os, sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import (
    NUM_NODES, FL_ROUNDS as NUM_ROUNDS, MIN_FIT_CLIENTS, MIN_EVAL_CLIENTS,
    FRACTION_FIT
)
from federation.irba import IRBATrustScorer
from model.fedaida_model import build_fedaida_model, get_model_weights


class IRBAFedAvg(Strategy):
    """
    Custom Flower Strategy: FedAvg with IRBA trust-weighted aggregation.
    
    Extends standard FedAvg by:
    1. Computing trust scores for each node using IRBATrustScorer
    2. Weighting aggregation by trust (not just data size)
    3. Excluding quarantined (Byzantine) nodes
    4. Logging all trust scores per round for paper figures
    """

    def __init__(self,
                 initial_parameters,
                 irba_scorer: IRBATrustScorer,
                 n_classes: int = 5,
                 fraction_fit: float = FRACTION_FIT,
                 min_fit_clients: int = MIN_FIT_CLIENTS,
                 min_eval_clients: int = MIN_EVAL_CLIENTS,
                 min_available_clients: int = NUM_NODES,
                 round_metrics_callback=None):

        self.initial_parameters       = initial_parameters
        self.irba                     = irba_scorer
        self.n_classes                = n_classes
        self.fraction_fit             = fraction_fit
        self.min_fit_clients          = min_fit_clients
        self.min_eval_clients         = min_eval_clients
        self.min_available_clients    = min_available_clients
        self.round_metrics_callback   = round_metrics_callback

        self.round_history = []  # Stores per-round metrics for paper figures

    def initialize_parameters(self, client_manager):
        return self.initial_parameters

    def configure_fit(self, server_round, parameters, client_manager):
        config = {'server_round': server_round}
        sample_size = max(
            self.min_fit_clients,
            int(client_manager.num_available() * self.fraction_fit)
        )
        clients = client_manager.sample(
            num_clients=sample_size,
            min_num_clients=self.min_fit_clients
        )
        return [(c, fl.common.FitIns(parameters, config)) for c in clients]

    def configure_evaluate(self, server_round, parameters, client_manager):
        config = {'server_round': server_round}
        clients = client_manager.sample(
            num_clients=self.min_eval_clients,
            min_num_clients=self.min_eval_clients
        )
        return [(c, fl.common.EvaluateIns(parameters, config)) for c in clients]

    def aggregate_fit(
        self,
        server_round: int,
        results: List[Tuple[ClientProxy, FitRes]],
        failures
    ):
        if not results:
            return None, {}

        # Extract weights and metadata from each client
        weights_list   = []
        node_data      = []

        for client, fit_res in results:
            w       = parameters_to_ndarrays(fit_res.parameters)
            n_samples = fit_res.num_examples
            metrics = fit_res.metrics or {}
            node_id = int(metrics.get('node_id', -1))
            weights_list.append((node_id, w, n_samples, metrics))

        # Get current global weights for delta computation
        global_w = parameters_to_ndarrays(self.initial_parameters)
        all_node_weights = [(nid, w) for nid, w, _, _ in weights_list]

        # ── IRBA Trust Scoring ────────────────────────────
        trust_weights = []
        # Build flat dict of all updates for cosine similarity
        all_updates_dict = {nid: w[0] for nid, w, _, _ in weights_list if w}
        for node_id, local_w, n_samples, metrics in weights_list:
            trust = self.irba.update_trust(
                node_id=node_id,
                weight_update=local_w[0],
                all_updates=all_updates_dict
            )
            trust_weights.append(trust)

        # ── Trust-Weighted Aggregation ────────────────────
        trust_arr = np.array(trust_weights)
        total = trust_arr.sum()
        if total < 1e-7:
            trust_arr = np.ones(len(trust_arr)) / len(trust_arr)
        else:
            trust_arr /= total

        # Aggregate each layer
        n_layers       = len(weights_list[0][1])
        aggregated     = []
        for layer_idx in range(n_layers):
            layer_agg = np.zeros_like(weights_list[0][1][layer_idx],
                                       dtype=np.float64)
            for i, (_, w, _, _) in enumerate(weights_list):
                layer_agg += trust_arr[i] * w[layer_idx].astype(np.float64)
            aggregated.append(layer_agg.astype(np.float32))

        # Update stored global weights
        self.initial_parameters = ndarrays_to_parameters(aggregated)

        # ── Log round metrics ─────────────────────────────
        irba_status = self.irba.get_status()
        round_metrics = {
            'round':          server_round,
            'trust_scores':   irba_status['trust_scores'],
            'quarantined':    irba_status['quarantined'],
            'n_active':       len([t for t in trust_arr if t > 0]),
            'avg_f1':         float(np.mean([
                                m.get('f1', 0) for _, _, _, m in weights_list
                              ])),
            'drift_nodes':    [
                nid for nid, _, _, m in weights_list
                if m.get('drift_detected', 0)
            ],
        }
        self.round_history.append(round_metrics)

        print(f"\n  [Server Round {server_round}] "
              f"Active nodes: {round_metrics['n_active']} | "
              f"Avg F1: {round_metrics['avg_f1']:.4f} | "
              f"Quarantined: {irba_status['quarantined']} | "
              f"Drift nodes: {round_metrics['drift_nodes']}")

        if self.round_metrics_callback:
            self.round_metrics_callback(round_metrics)

        return ndarrays_to_parameters(aggregated), round_metrics

    def aggregate_evaluate(self, server_round, results, failures):
        if not results:
            return None, {}
        total = sum(r.num_examples for _, r in results)
        avg_loss = sum(r.loss * r.num_examples for _, r in results) / total
        avg_f1   = np.mean([r.metrics.get('f1', 0) for _, r in results])
        print(f"  [Server Eval Round {server_round}] "
              f"loss={avg_loss:.4f} | f1={avg_f1:.4f}")
        return float(avg_loss), {'f1': float(avg_f1)}

    def evaluate(self, server_round, parameters):
        return None


def run_federation(clients, n_rounds=NUM_ROUNDS,
                   val_X=None, val_y=None,
                   n_classes=5,
                   byzantine_nodes=None,
                   round_callback=None):
    """
    Run the full federated training simulation.
    
    Args:
        clients:         list of FedAIDAClient instances
        n_rounds:        number of FL communication rounds
        val_X, val_y:    coordinator clean validation set for IRBA
        n_classes:       number of attack classes
        byzantine_nodes: list of node IDs to simulate as malicious
        round_callback:  optional function(round_metrics) for dashboard
    
    Returns:
        global_weights, round_history
    """
    from data.preprocess import create_sequences

    # Build initial global model
    global_model = build_fedaida_model(n_classes=n_classes)
    init_params  = ndarrays_to_parameters(get_model_weights(global_model))

    # Create IRBA scorer
    val_seq_X, val_seq_y = None, None
    if val_X is not None:
        from data.preprocess import create_sequences
        val_seq_X, val_seq_y = create_sequences(val_X, val_y,
                                                seq_len=global_model.input_shape[1])

    irba = IRBATrustScorer(
        n_nodes=len(clients),
        n_classes=n_classes
    )

    # Inject Byzantine nodes if testing poisoning defence
    if byzantine_nodes:
        print(f"\n[Byzantine Test] Poisoning nodes: {byzantine_nodes}")
        _inject_byzantine(clients, byzantine_nodes)

    # Create Flower strategy
    strategy = IRBAFedAvg(
        initial_parameters=init_params,
        irba_scorer=irba,
        n_classes=n_classes,
        round_metrics_callback=round_callback
    )

    # Flower simulation
    history = fl.simulation.start_simulation(
        client_fn=lambda cid: clients[int(cid)],
        num_clients=len(clients),
        config=fl.server.ServerConfig(num_rounds=n_rounds),
        strategy=strategy,
        client_resources={'num_cpus': 1, 'num_gpus': 0.0}
    )

    return strategy.initial_parameters, strategy.round_history, history


def _inject_byzantine(clients, byzantine_node_ids):
    """
    Simulate Byzantine attack: compromised nodes will invert their weights.
    We monkey-patch their fit() method.
    """
    for nid in byzantine_node_ids:
        if nid < len(clients):
            original_fit = clients[nid].fit

            def malicious_fit(parameters, config,
                              _orig=original_fit, _nid=nid):
                weights, n, metrics = _orig(parameters, config)
                # Invert weights to poison the global model
                poisoned = [-w for w in weights]
                metrics['byzantine'] = True
                print(f"  [Byzantine] Node {_nid} sending poisoned weights")
                return poisoned, n, metrics

            clients[nid].fit = malicious_fit
