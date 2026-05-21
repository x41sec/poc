/**
 * @name Use of untrusted starlette/fastapi url (MEDIUM)
 * @description Direct use of URL object from starlette/fastapi request. The URL
 *              may be manipulated via malformed Host header.
 * @kind problem
 * @problem.severity warning
 * @security-severity 6.0
 * @precision medium
 * @id py/starlette-url-usage
 * @tags security
 *       external/cwe/cwe-20
 */

import python
import semmle.python.dataflow.new.DataFlow
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
 * Gets API nodes for starlette/fastapi Request classes.
 */
API::Node starletteRequestApi() {
  result = API::moduleImport("fastapi").getMember("Request")
  or
  result = API::moduleImport("starlette").getMember("requests").getMember("Request")
  or
  result = API::moduleImport("starlette").getMember("requests").getMember("HTTPConnection")
}

/**
 * Finds accesses to .url on HTTPConnection/Request objects from starlette/fastapi.
 */
predicate isRequestUrlAccess(DataFlow::AttrRead attr) {
  attr.getAttributeName() = "url" and
  (
    // Type annotation approach
    exists(Function f, Parameter p |
      p = f.getAnArg() and
      attr.getObject().asExpr().(Name).getId() = p.getName() and
      p.getAnnotation().(Name).getId() = ["Request", "HTTPConnection"] and
      moduleImportsStarletteRequest(f.getEnclosingModule())
    )
    or
    // API graph approach
    attr.getObject() = starletteRequestApi().getAValueReachableFromSource()
  )
}

/**
 * Finds direct construction of starlette.datastructures.URL(...).
 */
predicate isStarletteUrlConstruction(DataFlow::CallCfgNode call) {
  call = API::moduleImport("starlette").getMember("datastructures").getMember("URL").getACall()
}

from DataFlow::Node node, string msg
where
  isRequestUrlAccess(node) and
  msg = "Use of potentially untrusted URL from starlette/fastapi request object."
  or
  isStarletteUrlConstruction(node) and
  msg = "Construction of starlette URL object - ensure Host header is validated."
select node, msg
