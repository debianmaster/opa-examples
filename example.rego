package authz

allow { 
    input.method == "GET" 
    input.path == "clusters"
    allowed[_]
}
allowed[x]=z {
    data.cluster_bindings[x].admin[z] = input.user
}