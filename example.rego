package authz

allow[cluster] { # user has admin permissions
    input.method == "GET"
    input.path == "clusters"
    data.clusters[cluster]
    data.clusters[cluster].metadata.rbac.admin[_] = input.user
}

allow[cluster] {  # user has readonly permissions
    input.method == "GET"
    input.path == "clusters"
    data.clusters[cluster]
    data.clusters[cluster].metadata.rbac.readyonly[_] = input.user
}

allow[cluster] {  # user has edit permission
    input.method == "PUT"
    input.path == "clusters"
    data.clusters[cluster]
    data.clusters[cluster].metadata.rbac.admin[_] = input.user
}

allow[cluster] { # user has admin permissions
    input.method == "PATCH"
    input.path == "clusters"
    data.clusters[cluster]
    data.clusters[cluster].metadata.rbac.admin[_] = input.user
}

allow[cluster] {  # user has access to create clusters
    input.method == "POST"
    input.path == "clusters"
    cluster := "true"
}