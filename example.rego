package authz


allow[c] { 
    input.method == "GET"
    input.path == "clusters"
    c := data.clusters[_]
    r := data.cluster_bindings[_]
    r.subjects[_].name = input.user
    contains(r.metadata.name,c.metadata.name)
}

