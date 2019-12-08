package authz

allow { 
    input.method == "GET" 
    input.path == "clusters" 
    allowed[_]
}
allowed[x]{
    data.cluster_bindings[x].admin[_] = input.user
}