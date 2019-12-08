package authz

allow { 
    input.method == "GET" 
    input.path == "clusters"
    allowed[_]
}
allowed[x] {
    data.clusters[x].metadata.rbac.admin[_] = input.user
}