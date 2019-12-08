package authz

allow { 
    input.method == "GET" 
    input.path == "clusters"
    allowed[_]
}
allowed{
    data.cluster_bindings[_].admin[_] = input.user
}