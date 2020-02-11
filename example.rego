package authz



allow[c] { 
    input.method == "GET"
    input.path == "clusters"
    c := data.clusters[_]
    r := data.cluster_bindings[_]
    c.kind == "Cluster"
    r.subjects[_].name = input.user
    anyrole := strings.replace_n({"-owner-rb":"","-administrator-rb":"","-operator-rb":"","-reader-rb":""}, r.metadata.name)
    anyrole_1 := replace(anyrole,"clusters-","")
    #chak1-mfgftgzuszkzfpl
    #clusters-chak1-mfgftgzuszkzfpl-administrator-rb
    anyrole_1 == c.metadata.name
}

