package authz

allow { 
    input.method == "GET" 
    input.path == "clusters" 
    allowed[_]
}
allowed[x]{
    data.clusters[x].metadata.name = data.user_bindings[input.user][_]
}