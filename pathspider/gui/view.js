function encode_key_values(key, values) {
    var params = [];
    for (var d in values) {
        params.push(encodeURIComponent(key) + "=" + encodeURIComponent(values[d]));
    }
    return params.join("&");
}

function view_generate(err, data, selector_svg) {
    if(err != null) {
        console.error(err);
    }
    
    var vis = d3.select(selector_svg);

    var force = d3.layout.force()
        .nodes(data.nodes)
        .links(data.links)
        .size([720, 680])
        .charge(-200)
        .start();
    
    var drag = force.drag()
        .on("dragstart", view_dragstart);
    
    force.on("tick", function(e) {
        
        vis.selectAll(".nodes")
            .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        
        vis.selectAll(".links")
            .attr("x1", function(d) { return d.source.x; })
            .attr("y1", function(d) { return d.source.y; })
            .attr("x2", function(d) { return d.target.x; })
            .attr("y2", function(d) { return d.target.y; })
    });
    
    // create nodes
    var dnodes = vis.selectAll(".nodes").data(data.nodes);
    var dnodesEnter = dnodes.enter();
    var dnodesEnterGroup = dnodesEnter.append("g");
    
    
    // - set class
    dnodesEnterGroup.classed("nodes", true)
        .on("dblclick", view_dblclick)
        .call(drag);
    
    // - add a circle
    dnodesEnterGroup.append("circle")
        .attr("r", 4)
    
    // - and some text
    dnodesEnterGroup.append("text")
      .attr("x", 20)
    
    
    dnodes.select("text")
      .text(function(d) { return d.caption; });
    
    dnodes.exit().remove();
    
    // create links
    dlinks = vis.selectAll(".links").data(data.links);
    dlinks.enter()
        .append("line")
    
    
    dlinks
        .attr("class", function(d) { return "links probe_"+d.probe; })
        .classed("links", true)
        .attr("style", function(d) {
            if(d.mode == "normal") {
            } else if(d.mode == "missing") {
                return "stroke:red;stroke-dasharray:5,5;stroke-width:2";
            }
        });
    
    dlinks.exit().remove();
}

function view_dblclick(d) {
    d3.select(this).classed("fixed", d.fixed = false);
}

function view_dragstart(d) {
    d3.select(this).classed("fixed", d.fixed = true);
}

function view_load(selector_svg, ips) {
    d3.json('http://localhost:37100/command/graph?'+encode_key_values("ip", ips),
        function(err, data) {
            view_generate(err, data, selector_svg);
        }
    );
}
