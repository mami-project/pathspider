

function state2color(state) {
  switch(state) {
    case 'safe': return "#00de41";
    case 'broken_site': return "#ff3c3c";
    case 'broken_path': return "#ff840c";
    case 'broken_other': return "#f1ff15";
    case 'unknown': return "#d27bff";
  }
}

function update_chart(selector, data) {
  var color = d3.scale.category20();
  var vis = d3.select(selector);
  
  var bb = vis.node().getBoundingClientRect();
  var radius = Math.min(bb.width, bb.height) / 2;
  
  var pie = d3.layout.pie()
    .value(function(d) { return d[1]; })
    .sort(null);
    
  var arc = d3.svg.arc()
    .innerRadius(radius*0.4)
    .outerRadius(radius*0.9);
    
  // create center if needed
  var g = vis.select("g");
  if(g.empty()) {
    g = vis.append("g");
  }
  g.attr("transform", "translate(" + bb.width / 2 + "," + bb.height / 2 + ")");
  
    
  var path = g.datum(data).selectAll("path").data(pie);
  
  path.enter().append("path");
  
  path.attr("fill", function(d, i) { return state2color(d.data[0]); });
  path.attr("d", arc);
  
  path.exit().remove();
}

