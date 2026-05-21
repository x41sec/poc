/**
 * @name Heuristic detection of request url.path usage (LOW)
 * @description Accessing .path on .url of variables with 'req' in their name.
 *              This is a heuristic/low-confidence detection.
 * @kind path-problem
 * @problem.severity recommendation
 * @security-severity 3.0
 * @precision low
 * @id py/heuristic-req-url-path
 * @tags security
 *       external/cwe/cwe-20
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking

/**
 * A source: .url access on any variable containing "req" in its name.
 * Matches patterns like: request.url, req.url, http_request.url, etc.
 */
predicate isHeuristicReqUrlSource(DataFlow::Node node) {
  exists(DataFlow::AttrRead attr |
    attr.getAttributeName() = "url" and
    node = attr and
    // Variable name contains "req" (case insensitive via lowercase check)
    exists(string varName |
      varName = attr.getObject().asExpr().(Name).getId() and
      varName.toLowerCase().matches("%req%")
    )
  )
}

/**
 * A sink where .path is accessed.
 */
predicate isUrlPathSink(DataFlow::Node node, DataFlow::AttrRead pathAccess) {
  pathAccess.getAttributeName() = "path" and
  node = pathAccess.getObject()
}

module HeuristicUrlPathConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isHeuristicReqUrlSource(source) }

  predicate isSink(DataFlow::Node sink) { isUrlPathSink(sink, _) }
}

module HeuristicUrlPathTaint = TaintTracking::Global<HeuristicUrlPathConfig>;

import HeuristicUrlPathTaint::PathGraph

from HeuristicUrlPathTaint::PathNode source, HeuristicUrlPathTaint::PathNode sink, DataFlow::AttrRead pathAccess
where
  HeuristicUrlPathTaint::flowPath(source, sink) and
  isUrlPathSink(sink.getNode(), pathAccess)
select pathAccess, source, sink,
  "Potential untrusted .path access from $@ (heuristic match on variable name containing 'req').",
  source.getNode(), "request-like .url"
