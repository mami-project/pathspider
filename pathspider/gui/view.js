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
    vis.selectAll("*").remove();
    
    var bb = vis.node().getBoundingClientRect();
    
    if(vis.select("g.linkgroup").empty()) {
        vis.append("g").classed("linkgroup", true);
    }
    if(vis.select("g.nodegroup").empty()) {
        vis.append("g").classed("nodegroup", true);
    }

    var force = d3.layout.force()
        .nodes(data.nodes)
        .links(data.links)
        .size([bb.width, bb.height])
        .gravity(0.05)
        .distance(50)
        .charge(-100)
        .start();
    
    // precompute
    for (var i = 0; i < 200; ++i) {
        force.tick();
    }
    
    function view_tick() {
        vis.selectAll("g.nodegroup .nodes")
            .attr("transform", function(d) { return "translate(" + d.x + "," + d.y + ")"; });
        
        vis.select("g.linkgroup").selectAll(".links")
            .attr("x1", function(d) { return d.source.x; })
            .attr("y1", function(d) { return d.source.y; })
            .attr("x2", function(d) { return d.target.x; })
            .attr("y2", function(d) { return d.target.y; })
    }
    
    function view_dblclick(d) {
        d3.select(this).classed("fixed", d.fixed = false);
    }

    function view_dragstart(d, i) {
        force.stop();
    }

    function view_dragmove(d, i) {
        d.px += d3.event.dx;
        d.py += d3.event.dy;
        d.x += d3.event.dx;
        d.y += d3.event.dy;
        view_tick();
    }

    function view_dragend(d) {
        //d.fixed = true;
        view_tick();
        force.resume();
    }
    
    var drag = force.drag()
        .on("dragstart", view_dragstart)
        .on("drag", view_dragmove)
        .on("dragend", view_dragend);
    
    force.on("tick", view_tick);
    
    // create nodes
    var dnodes = vis.select(".nodegroup").selectAll(".nodes").data(data.nodes);
    var dnodesEnter = dnodes.enter();
    var dnodesEnterGroup = dnodesEnter.append("g");
    
    
    // - set class
    dnodesEnterGroup.classed("nodes", true)
        .on("dblclick", view_dblclick)
        .call(drag);
    
    // - add a circle
    dnodesEnterGroup.append("circle")
        .attr("r", 8)
    
    dnodes.exit().remove();
    
    // create links
    dlinks = vis.select(".linkgroup").selectAll(".links").data(data.links);
    dlinks.enter()
        .append("line");
    
    dlinks
        .attr("class", function(d) { return d.classes; })
        .classed("links", true)
        .attr("style", function(d) {
            if(d.mode == "normal") {
            } else if(d.mode == "missing") {
                return "stroke:red;stroke-dasharray:5,5;stroke-width:2";
            }
        });
    
    dlinks.exit().remove();
    
    $('.linkgroup .links').tipsy({ 
        gravity: 'w', 
        html: true, 
        title: function() {
          var d = this.__data__;
          return d.caption;
        }
    });
    $('.nodegroup .nodes').tipsy({ 
        gravity: 'w', 
        html: true, 
        title: function() {
          var d = this.__data__;
          return d.caption;
        }
    });
}



function view_load(selector_svg, ips) {
    d3.json('http://localhost:37100/command/graph?'+encode_key_values("ip", ips),
        function(err, data) {
            view_generate(err, data, selector_svg);
        }
    );
}
