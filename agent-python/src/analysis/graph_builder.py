from typing import Any, Dict, List

import math
import networkx as nx


class GraphBuilder:
    def build_entity_graph(
        self,
        entity_type: str,
        entity_id: str,
        record: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> nx.Graph:
        graph = nx.Graph()

        root_node = self._root_node_id(entity_type, entity_id)
        graph.add_node(
            root_node,
            node_type=entity_type,
            label=entity_id,
            entity_id=entity_id,
        )

        if entity_type == "cve":
            self._attach_cve_context(graph, root_node, record, evidence)
        elif entity_type == "urlhaus":
            self._attach_urlhaus_context(graph, root_node, record, evidence)
        elif entity_type == "dread":
            self._attach_dread_context(graph, root_node, record, evidence)

        return graph

    def summarize_graph(self, graph: nx.Graph, root_node: str) -> Dict[str, Any]:
        node_count = graph.number_of_nodes()
        edge_count = graph.number_of_edges()

        degree_centrality = nx.degree_centrality(graph) if node_count > 1 else {root_node: 0.0}
        betweenness_centrality = (
            nx.betweenness_centrality(graph, normalized=True) if node_count > 2 else {root_node: 0.0}
        )
        closeness_centrality = nx.closeness_centrality(graph) if node_count > 1 else {root_node: 0.0}
        eigenvector_centrality = self._safe_eigenvector_centrality(graph, root_node)
        pagerank = self._safe_pagerank(graph, root_node)

        root_degree = float(degree_centrality.get(root_node, 0.0))
        root_betweenness = float(betweenness_centrality.get(root_node, 0.0))
        root_closeness = float(closeness_centrality.get(root_node, 0.0))
        root_eigenvector = float(eigenvector_centrality.get(root_node, 0.0))
        root_pagerank = float(pagerank.get(root_node, 0.0))

        connected_components = list(nx.connected_components(graph))
        largest_component_size = max((len(comp) for comp in connected_components), default=1)
        density = nx.density(graph) if node_count > 1 else 0.0
        average_clustering = nx.average_clustering(graph) if node_count > 2 else 0.0
        diameter_proxy = self._diameter_proxy(graph)

        neighbor_types = self._count_neighbor_types(graph, root_node)
        relation_distribution = self._count_relation_types(graph, root_node)
        provenance_distribution = self._count_provenance_sources(graph, root_node)
        evidence_distribution = self._count_evidence_types(graph, root_node)
        average_edge_confidence = self._average_edge_confidence(graph, root_node)
        weighted_degree = self._root_weighted_degree(graph, root_node)
        root_neighbors = list(graph.neighbors(root_node)) if root_node in graph else []
        cross_source_edge_count = sum(1 for neighbor in root_neighbors if graph[root_node][neighbor].get("evidence_type") == "cross_source_correlation")
        ioc_edge_count = sum(1 for neighbor in root_neighbors if graph.nodes[neighbor].get("node_type") == "ioc" and graph[root_node][neighbor].get("evidence_type") == "cross_source_correlation")
        provenance_diversity = self._normalized_diversity(provenance_distribution)
        relation_diversity = self._normalized_diversity(relation_distribution)
        evidence_diversity = self._normalized_diversity(evidence_distribution)
        root_component_ratio = round((largest_component_size / max(node_count, 1)), 4)

        centrality_score = self._calculate_centrality_score(
            degree=root_degree,
            betweenness=root_betweenness,
            closeness=root_closeness,
            eigenvector=root_eigenvector,
            pagerank=root_pagerank,
            weighted_degree=weighted_degree,
            density=density,
            average_edge_confidence=average_edge_confidence,
            provenance_diversity=provenance_diversity,
            relation_diversity=relation_diversity,
            evidence_diversity=evidence_diversity,
            node_count=node_count,
            edge_count=edge_count,
            neighbor_type_count=len(neighbor_types),
            root_component_ratio=root_component_ratio,
        )

        structural_strength = self._structural_strength(
            density=density,
            average_clustering=average_clustering,
            average_edge_confidence=average_edge_confidence,
            weighted_degree=weighted_degree,
            root_component_ratio=root_component_ratio,
        )

        return {
            "node_count": node_count,
            "edge_count": edge_count,
            "connected_component_count": len(connected_components),
            "largest_component_size": largest_component_size,
            "graph_density": round(float(density), 4),
            "average_clustering": round(float(average_clustering), 4),
            "diameter_proxy": diameter_proxy,
            "root_degree_centrality": round(root_degree, 4),
            "root_betweenness_centrality": round(root_betweenness, 4),
            "root_closeness_centrality": round(root_closeness, 4),
            "root_eigenvector_centrality": round(root_eigenvector, 4),
            "root_pagerank": round(root_pagerank, 4),
            "root_weighted_degree": round(weighted_degree, 4),
            "root_component_ratio": root_component_ratio,
            "cross_source_edge_count": int(cross_source_edge_count),
            "ioc_edge_count": int(ioc_edge_count),
            "neighbor_type_distribution": neighbor_types,
            "relation_distribution": relation_distribution,
            "provenance_distribution": provenance_distribution,
            "evidence_type_distribution": evidence_distribution,
            "provenance_diversity": provenance_diversity,
            "relation_diversity": relation_diversity,
            "evidence_diversity": evidence_diversity,
            "average_edge_confidence": average_edge_confidence,
            "structural_strength": round(structural_strength, 4),
            "centrality_score": round(centrality_score, 4),
            "graph_explanation": self._build_graph_explanation(
                node_count=node_count,
                edge_count=edge_count,
                density=density,
                average_edge_confidence=average_edge_confidence,
                provenance_diversity=provenance_diversity,
                relation_diversity=relation_diversity,
                root_component_ratio=root_component_ratio,
                centrality_score=centrality_score,
            ),
        }

    def export_graph_edges(self, graph: nx.Graph, limit: int = 25) -> List[Dict[str, Any]]:
        edges: List[Dict[str, Any]] = []

        for idx, (source, target, attrs) in enumerate(graph.edges(data=True)):
            if idx >= limit:
                break
            edges.append(
                {
                    "source": source,
                    "target": target,
                    "relation": attrs.get("relation"),
                    "weight": attrs.get("weight", 1.0),
                    "confidence": attrs.get("confidence", 0.0),
                    "evidence_type": attrs.get("evidence_type", "context_link"),
                    "provenance": attrs.get("provenance", "derived"),
                    "explanation": attrs.get("explanation", ""),
                }
            )

        return edges

    def _attach_cve_context(
        self,
        graph: nx.Graph,
        root_node: str,
        record: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> None:
        keywords = evidence.get("keywords", []) or []
        products = evidence.get("llm_products", []) or []
        vuln_type = evidence.get("llm_vuln_type")
        impact = evidence.get("llm_impact")
        dread_categories = evidence.get("dread_categories", []) or []

        published = record.get("published")
        if published:
            time_node = f"time:{published[:10]}"
            graph.add_node(time_node, node_type="time", label=published[:10])
            self._add_edge(
                graph, root_node, time_node,
                relation="published_on", weight=0.4, confidence=0.98,
                provenance="cve", evidence_type="record_metadata",
                explanation="Publication timestamp was linked from the CVE record.",
            )

        cvss_score = evidence.get("cvss_score")
        if cvss_score is not None:
            severity_node = f"cvss:{cvss_score}"
            graph.add_node(severity_node, node_type="cvss", label=str(cvss_score))
            self._add_edge(
                graph, root_node, severity_node,
                relation="has_cvss", weight=0.8, confidence=0.99,
                provenance="cve", evidence_type="scoring_metadata",
                explanation="CVSS severity metadata was attached to the CVE node.",
            )

        for product in products[:8]:
            product_node = f"product:{str(product).strip().lower()}"
            graph.add_node(product_node, node_type="product", label=str(product))
            self._add_edge(
                graph, root_node, product_node,
                relation="affects_product", weight=1.0, confidence=0.84,
                provenance="llm_extraction", evidence_type="semantic_extraction",
                explanation="Affected product was extracted from the CVE description.",
            )

        if vuln_type:
            vuln_node = f"vuln_type:{str(vuln_type).strip().lower()}"
            graph.add_node(vuln_node, node_type="vuln_type", label=str(vuln_type))
            self._add_edge(
                graph, root_node, vuln_node,
                relation="has_vuln_type", weight=1.0, confidence=0.82,
                provenance="llm_extraction", evidence_type="semantic_extraction",
                explanation="Vulnerability type was extracted from the CVE description.",
            )

        if impact:
            impact_node = f"impact:{str(impact).strip().lower()[:60]}"
            graph.add_node(impact_node, node_type="impact", label=str(impact))
            self._add_edge(
                graph, root_node, impact_node,
                relation="has_impact", weight=0.7, confidence=0.78,
                provenance="llm_extraction", evidence_type="semantic_extraction",
                explanation="Likely attacker impact was extracted from descriptive context.",
            )

        for kw in keywords[:10]:
            kw_node = f"keyword:{kw}"
            graph.add_node(kw_node, node_type="keyword", label=kw)
            self._add_edge(
                graph, root_node, kw_node,
                relation="mentions_keyword", weight=0.3, confidence=0.68,
                provenance="keyword_extractor", evidence_type="keyword_overlap",
                explanation=f"Keyword '{kw}' contributes to cross-source matching and graph context.",
            )

        for category in dread_categories[:6]:
            category_node = f"dread_category:{category}"
            graph.add_node(category_node, node_type="threat_category", label=category)
            self._add_edge(
                graph, root_node, category_node,
                relation="linked_darkweb_signal", weight=0.8, confidence=0.73,
                provenance="dread", evidence_type="cross_source_correlation",
                explanation="Related dark-web activity category was found through correlated Dread records.",
            )

        for item in evidence.get("sample_urlhaus_hits", [])[:5]:
            url = item.get("url")
            if not url:
                continue
            url_node = f"urlhaus:{url}"
            graph.add_node(url_node, node_type="ioc", label=url, threat=item.get("threat"))
            confidence = 0.86 if str(item.get("url_status", "")).lower() == "online" else 0.78
            self._add_edge(
                graph, root_node, url_node,
                relation="correlated_urlhaus", weight=1.2, confidence=confidence,
                provenance="urlhaus", evidence_type="cross_source_correlation",
                explanation="URLhaus IOC correlated with the CVE through shared keywords and threat context.",
            )

            tags = item.get("tags") or []
            for tag in tags[:5]:
                tag_node = f"tag:{str(tag).strip().lower()}"
                graph.add_node(tag_node, node_type="tag", label=str(tag))
                self._add_edge(
                    graph, url_node, tag_node,
                    relation="has_tag", weight=0.6, confidence=0.92,
                    provenance="urlhaus", evidence_type="feed_tag",
                    explanation="IOC tag was attached directly from the URLhaus feed.",
                )

        for item in evidence.get("sample_dread_hits", [])[:5]:
            title = item.get("title")
            if not title:
                continue
            dread_node = f"dread:{title.strip().lower()[:80]}"
            graph.add_node(
                dread_node,
                node_type="darkweb_post",
                label=title,
                category=item.get("category"),
                author=item.get("author"),
            )
            self._add_edge(
                graph, root_node, dread_node,
                relation="correlated_dread", weight=1.1, confidence=0.71,
                provenance="dread", evidence_type="cross_source_correlation",
                explanation="Dark-web discussion was linked to the CVE through extracted threat keywords.",
            )

    def _attach_urlhaus_context(
        self,
        graph: nx.Graph,
        root_node: str,
        record: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> None:
        url = record.get("url")
        threat = evidence.get("threat")
        status = evidence.get("url_status")
        tags = evidence.get("tags", []) or []
        keywords = evidence.get("keywords", []) or []

        if url:
            url_node = f"url:{url}"
            graph.add_node(url_node, node_type="url", label=url)
            self._add_edge(
                graph, root_node, url_node,
                relation="represents_url", weight=1.0, confidence=0.99,
                provenance="urlhaus", evidence_type="record_metadata",
                explanation="Primary malicious URL node was attached from the URLhaus record.",
            )

        if threat:
            threat_node = f"threat:{str(threat).strip().lower()}"
            graph.add_node(threat_node, node_type="threat", label=str(threat))
            self._add_edge(
                graph, root_node, threat_node,
                relation="indicates_threat", weight=1.0, confidence=0.93,
                provenance="urlhaus", evidence_type="feed_label",
                explanation="Threat label came directly from URLhaus feed metadata.",
            )

        if status:
            status_node = f"status:{str(status).strip().lower()}"
            graph.add_node(status_node, node_type="status", label=str(status))
            self._add_edge(
                graph, root_node, status_node,
                relation="has_status", weight=0.5, confidence=0.96,
                provenance="urlhaus", evidence_type="feed_status",
                explanation="IOC operational status was attached from URLhaus metadata.",
            )

        for tag in tags[:8]:
            tag_node = f"tag:{str(tag).strip().lower()}"
            graph.add_node(tag_node, node_type="tag", label=str(tag))
            self._add_edge(
                graph, root_node, tag_node,
                relation="has_tag", weight=0.8, confidence=0.93,
                provenance="urlhaus", evidence_type="feed_tag",
                explanation="IOC tag came directly from URLhaus feed tagging.",
            )

        for kw in keywords[:8]:
            kw_node = f"keyword:{kw}"
            graph.add_node(kw_node, node_type="keyword", label=kw)
            self._add_edge(
                graph, root_node, kw_node,
                relation="mentions_keyword", weight=0.3, confidence=0.66,
                provenance="keyword_extractor", evidence_type="keyword_overlap",
                explanation=f"Keyword '{kw}' supports correlation and graph context for the IOC.",
            )

        for item in evidence.get("sample_related_cves", [])[:5]:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            cve_node = f"cve:{cve_id}"
            graph.add_node(cve_node, node_type="cve", label=cve_id)
            self._add_edge(
                graph, root_node, cve_node,
                relation="related_cve", weight=1.1, confidence=0.76,
                provenance="cve", evidence_type="cross_source_correlation",
                explanation="The IOC was linked to a CVE through shared threat indicators or keywords.",
            )

        for item in evidence.get("sample_dread_hits", [])[:5]:
            title = item.get("title")
            if not title:
                continue
            dread_node = f"dread:{title.strip().lower()[:80]}"
            graph.add_node(dread_node, node_type="darkweb_post", label=title)
            self._add_edge(
                graph, root_node, dread_node,
                relation="related_darkweb_post", weight=0.9, confidence=0.68,
                provenance="dread", evidence_type="cross_source_correlation",
                explanation="Dark-web post was linked through overlapping malicious indicators.",
            )

    def _attach_dread_context(
        self,
        graph: nx.Graph,
        root_node: str,
        record: Dict[str, Any],
        evidence: Dict[str, Any],
    ) -> None:
        author = record.get("author")
        category = record.get("category")
        keywords = evidence.get("keywords", []) or []
        matched_terms = evidence.get("matched_terms", []) or []
        categories = evidence.get("categories", []) or []
        llm_category = evidence.get("llm_category")

        if author:
            author_node = f"author:{str(author).strip().lower()}"
            graph.add_node(author_node, node_type="author", label=str(author))
            self._add_edge(
                graph, root_node, author_node,
                relation="written_by", weight=0.5, confidence=0.95,
                provenance="dread", evidence_type="record_metadata",
                explanation="Author metadata was linked from the forum post.",
            )

        if category:
            forum_node = f"forum_category:{str(category).strip().lower()}"
            graph.add_node(forum_node, node_type="forum_category", label=str(category))
            self._add_edge(
                graph, root_node, forum_node,
                relation="posted_in_category", weight=0.6, confidence=0.94,
                provenance="dread", evidence_type="record_metadata",
                explanation="Forum category was attached from the Dread record metadata.",
            )

        for kw in keywords[:10]:
            kw_node = f"keyword:{kw}"
            graph.add_node(kw_node, node_type="keyword", label=kw)
            self._add_edge(
                graph, root_node, kw_node,
                relation="mentions_keyword", weight=0.3, confidence=0.65,
                provenance="keyword_extractor", evidence_type="keyword_overlap",
                explanation=f"Keyword '{kw}' supports correlation against CVE and IOC sources.",
            )

        for term in matched_terms[:8]:
            term_node = f"term:{str(term).strip().lower()}"
            graph.add_node(term_node, node_type="matched_term", label=str(term))
            self._add_edge(
                graph, root_node, term_node,
                relation="matched_classifier_term", weight=0.8, confidence=0.79,
                provenance="rule_classifier", evidence_type="classifier_match",
                explanation="Threat-classifier term matched known dark-web risk patterns.",
            )

        for item in categories[:6]:
            category_node = f"activity:{str(item).strip().lower()}"
            graph.add_node(category_node, node_type="activity_category", label=str(item))
            self._add_edge(
                graph, root_node, category_node,
                relation="classified_as", weight=1.0, confidence=0.82,
                provenance="rule_classifier", evidence_type="classifier_match",
                explanation="The post was classified into a risk-relevant dark-web activity category.",
            )

        if llm_category:
            llm_node = f"llm_category:{str(llm_category).strip().lower()}"
            graph.add_node(llm_node, node_type="llm_category", label=str(llm_category))
            self._add_edge(
                graph, root_node, llm_node,
                relation="llm_classified_as", weight=0.9, confidence=0.78,
                provenance="llm_classifier", evidence_type="semantic_classification",
                explanation="An LLM supplied a supporting classification for the dark-web post.",
            )

        for item in evidence.get("sample_related_cves", [])[:5]:
            cve_id = item.get("cve_id")
            if not cve_id:
                continue
            cve_node = f"cve:{cve_id}"
            graph.add_node(cve_node, node_type="cve", label=cve_id)
            self._add_edge(
                graph, root_node, cve_node,
                relation="mentions_or_relates_cve", weight=1.0, confidence=0.75,
                provenance="cve", evidence_type="cross_source_correlation",
                explanation="The dark-web post appears to reference or align with a known CVE.",
            )

        for item in evidence.get("sample_related_urlhaus", [])[:5]:
            url = item.get("url")
            if not url:
                continue
            url_node = f"urlhaus:{url}"
            graph.add_node(url_node, node_type="ioc", label=url)
            self._add_edge(
                graph, root_node, url_node,
                relation="mentions_or_relates_ioc", weight=0.9, confidence=0.69,
                provenance="urlhaus", evidence_type="cross_source_correlation",
                explanation="The post overlaps with IOC activity seen in URLhaus records.",
            )

    def _root_node_id(self, entity_type: str, entity_id: str) -> str:
        return f"{entity_type}:{entity_id}"

    def _calculate_centrality_score(
        self,
        degree: float,
        betweenness: float,
        closeness: float,
        eigenvector: float,
        pagerank: float,
        weighted_degree: float,
        density: float,
        average_edge_confidence: float,
        provenance_diversity: float,
        relation_diversity: float,
        evidence_diversity: float,
        node_count: int,
        edge_count: int,
        neighbor_type_count: int,
        root_component_ratio: float,
    ) -> float:
        structural_bonus = min(node_count * 0.035, 0.55) + min(edge_count * 0.025, 0.45)
        diversity_bonus = min(neighbor_type_count * 0.07, 0.35)
        centrality_component = (
            (degree * 0.25)
            + (betweenness * 0.18)
            + (closeness * 0.12)
            + (eigenvector * 0.18)
            + (pagerank * 1.15)
        )
        support_component = (
            min(weighted_degree * 0.06, 0.22)
            + (density * 0.25)
            + (average_edge_confidence * 0.16)
            + (provenance_diversity * 0.12)
            + (relation_diversity * 0.10)
            + (evidence_diversity * 0.08)
            + (root_component_ratio * 0.08)
        )
        return min(centrality_component + structural_bonus + diversity_bonus + support_component, 1.8)

    def _count_neighbor_types(self, graph: nx.Graph, root_node: str) -> Dict[str, int]:
        if root_node not in graph:
            return {}
        distribution: Dict[str, int] = {}
        for neighbor in graph.neighbors(root_node):
            node_type = graph.nodes[neighbor].get("node_type", "unknown")
            distribution[node_type] = distribution.get(node_type, 0) + 1
        return distribution

    def _count_relation_types(self, graph: nx.Graph, root_node: str) -> Dict[str, int]:
        if root_node not in graph:
            return {}
        distribution: Dict[str, int] = {}
        for neighbor in graph.neighbors(root_node):
            relation = graph.get_edge_data(root_node, neighbor).get("relation", "related_to")
            distribution[relation] = distribution.get(relation, 0) + 1
        return distribution

    def _count_provenance_sources(self, graph: nx.Graph, root_node: str) -> Dict[str, int]:
        if root_node not in graph:
            return {}
        distribution: Dict[str, int] = {}
        for neighbor in graph.neighbors(root_node):
            provenance = graph.get_edge_data(root_node, neighbor).get("provenance", "derived")
            distribution[provenance] = distribution.get(provenance, 0) + 1
        return distribution

    def _count_evidence_types(self, graph: nx.Graph, root_node: str) -> Dict[str, int]:
        if root_node not in graph:
            return {}
        distribution: Dict[str, int] = {}
        for neighbor in graph.neighbors(root_node):
            evidence_type = graph.get_edge_data(root_node, neighbor).get("evidence_type", "context_link")
            distribution[evidence_type] = distribution.get(evidence_type, 0) + 1
        return distribution

    def _average_edge_confidence(self, graph: nx.Graph, root_node: str) -> float:
        if root_node not in graph:
            return 0.0
        confidences = []
        for neighbor in graph.neighbors(root_node):
            confidences.append(float(graph.get_edge_data(root_node, neighbor).get("confidence", 0.0)))
        if not confidences:
            return 0.0
        return round(sum(confidences) / len(confidences), 4)

    def _safe_eigenvector_centrality(self, graph: nx.Graph, root_node: str) -> Dict[str, float]:
        if graph.number_of_nodes() <= 1:
            return {root_node: 0.0}
        try:
            return nx.eigenvector_centrality_numpy(graph, weight="weight")
        except Exception:
            return {node: 0.0 for node in graph.nodes}

    def _safe_pagerank(self, graph: nx.Graph, root_node: str) -> Dict[str, float]:
        if graph.number_of_nodes() <= 1:
            return {root_node: 0.0}
        try:
            return nx.pagerank(graph, weight="weight")
        except Exception:
            return {node: 0.0 for node in graph.nodes}

    def _diameter_proxy(self, graph: nx.Graph) -> int:
        if graph.number_of_nodes() <= 1:
            return 0
        try:
            largest = max(nx.connected_components(graph), key=len)
            sub = graph.subgraph(largest)
            if sub.number_of_nodes() <= 1:
                return 0
            return int(nx.diameter(sub))
        except Exception:
            return 0

    def _root_weighted_degree(self, graph: nx.Graph, root_node: str) -> float:
        if root_node not in graph:
            return 0.0
        total = 0.0
        for neighbor in graph.neighbors(root_node):
            edge = graph.get_edge_data(root_node, neighbor) or {}
            total += float(edge.get("weight", 0.0)) * max(float(edge.get("confidence", 0.0)), 0.05)
        return total

    def _normalized_diversity(self, distribution: Dict[str, int]) -> float:
        total = sum(distribution.values())
        if total <= 1 or len(distribution) <= 1:
            return 0.0
        entropy = 0.0
        for count in distribution.values():
            p = count / total
            entropy -= p * math.log(p, 2)
        max_entropy = math.log(len(distribution), 2)
        if max_entropy <= 0:
            return 0.0
        return round(entropy / max_entropy, 4)

    def _structural_strength(
        self,
        density: float,
        average_clustering: float,
        average_edge_confidence: float,
        weighted_degree: float,
        root_component_ratio: float,
    ) -> float:
        return min(
            (density * 0.28)
            + (average_clustering * 0.18)
            + (average_edge_confidence * 0.22)
            + min(weighted_degree * 0.05, 0.18)
            + (root_component_ratio * 0.14),
            1.0,
        )

    def _build_graph_explanation(
        self,
        node_count: int,
        edge_count: int,
        density: float,
        average_edge_confidence: float,
        provenance_diversity: float,
        relation_diversity: float,
        root_component_ratio: float,
        centrality_score: float,
    ) -> List[str]:
        lines: List[str] = []
        lines.append(f"Graph contains {node_count} nodes and {edge_count} edges around the focal entity.")
        lines.append(f"Graph density is {density:.3f} and average edge confidence is {average_edge_confidence:.3f}.")
        if provenance_diversity > 0:
            lines.append(f"Evidence provenance diversity is {provenance_diversity:.3f}, indicating multi-source support.")
        if relation_diversity > 0:
            lines.append(f"Relation diversity is {relation_diversity:.3f}, suggesting non-trivial context variety.")
        lines.append(f"The focal entity participates in {root_component_ratio:.2%} of the largest connected component.")
        lines.append(f"Composite graph support score is {centrality_score:.3f}.")
        return lines

    def _add_edge(
        self,
        graph: nx.Graph,
        source: str,
        target: str,
        relation: str,
        weight: float,
        confidence: float,
        provenance: str,
        evidence_type: str,
        explanation: str,
    ) -> None:
        graph.add_edge(
            source,
            target,
            relation=relation,
            weight=weight,
            confidence=round(float(confidence), 2),
            provenance=provenance,
            evidence_type=evidence_type,
            explanation=explanation,
        )
