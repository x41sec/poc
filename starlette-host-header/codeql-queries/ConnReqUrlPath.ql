/**
 * @name Use of untrusted starlette/fastapi url.path (CRITICAL)
 * @description Accessing .path on a URL object from starlette/fastapi request can be
 *              manipulated via malformed Host header, bypassing path-based security checks.
 * @kind path-problem
 * @problem.severity error
 * @security-severity 9.0
 * @precision high
 * @id py/starlette-url-path-injection
 * @tags security
 *       external/cwe/cwe-20
 */

import python
import semmle.python.dataflow.new.DataFlow
import semmle.python.dataflow.new.TaintTracking
import semmle.python.ApiGraphs

/**
 * Holds if the module imports Request/HTTPConnection from starlette/fastapi.
 */
predicate moduleImportsStarletteRequest(Module m) {
  exists(Import i |
    i.getEnclosingModule() = m and
    (
      i.getAnImportedModuleName() = "fastapi.Request" or
      i.getAnImportedModuleName() = "starlette.requests.Request" or
      i.getAnImportedModuleName() = "starlette.requests.HTTPConnection"
    )
  )
}

/**
 * Gets API nodes for starlette/fastapi Request classes (for direct dataflow cases).
 */
API::Node starletteRequestApi() {
  result = API::moduleImport("fastapi").getMember("Request")
  or
  result = API::moduleImport("starlette").getMember("requests").getMember("Request")
  or
  result = API::moduleImport("starlette").getMember("requests").getMember("HTTPConnection")
}

/**
 * A source of tainted URL data from starlette/fastapi request objects.
 */
predicate isStarletteUrlSource(DataFlow::Node node) {
  // Type annotation approach: param: Request where module imports from fastapi/starlette
  exists(DataFlow::AttrRead attr, Function f, Parameter p |
    attr.getAttributeName() = "url" and
    node = attr and
    p = f.getAnArg() and
    attr.getObject().asExpr().(Name).getId() = p.getName() and
    p.getAnnotation().(Name).getId() = ["Request", "HTTPConnection"] and
    moduleImportsStarletteRequest(f.getEnclosingModule())
  )
  or
  // API graph approach: direct dataflow from import
  exists(DataFlow::AttrRead attr |
    attr.getAttributeName() = "url" and
    node = attr and
    attr.getObject() = starletteRequestApi().getAValueReachableFromSource()
  )
  or
  // Direct construction: starlette.datastructures.URL(...)
  node = API::moduleImport("starlette").getMember("datastructures").getMember("URL").getACall()
}

/**
 * A sink where .path is accessed on a tainted URL object.
 */
predicate isUrlPathSink(DataFlow::Node node, DataFlow::AttrRead pathAccess) {
  pathAccess.getAttributeName() = "path" and
  node = pathAccess.getObject()
}

module UrlPathTaintConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node source) { isStarletteUrlSource(source) }

  predicate isSink(DataFlow::Node sink) { isUrlPathSink(sink, _) }
}

module UrlPathTaint = TaintTracking::Global<UrlPathTaintConfig>;

import UrlPathTaint::PathGraph

from UrlPathTaint::PathNode source, UrlPathTaint::PathNode sink, DataFlow::AttrRead pathAccess
where
  UrlPathTaint::flowPath(source, sink) and
  isUrlPathSink(sink.getNode(), pathAccess)
select pathAccess, source, sink,
  "Untrusted URL .path access from $@ may be manipulated via Host header injection.",
  source.getNode(), "starlette/fastapi request.url"
