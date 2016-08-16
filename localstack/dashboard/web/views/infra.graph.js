(function () {
  'use strict'

  var app = angular.module('app');

  app.controller('graphCtrl', function($scope, $http, appConfig, restClient) {

    var client = restClient;
    var paper = null;
    var graph = null;
    var graphData = null;

    var canvas = $('#graph');

    var resize = function() {
      return;
      paper.setDimensions(canvas.width(), canvas.height());
    };

    var drawGraph = function() {

      if(!graphData) return;

      canvas.html('');

      jsPlumb.ready(function () {

        var j = jsPlumb.getInstance({Container:canvas, Connector:"StateMachine", Endpoint:["Dot", {radius:3}], Anchor:"Center"});

        var templates = {};
        $http({
            url: "/views/templates.html"
        }).success(function (data, status, headers, config) {

          /* map of elements to render */
          var components = {};
          /* graph margins */
          var marginLeft = 20;
          var marginTop = 20;


          data = $.parseHTML(data);
          $(data).children().each(function(i,c) {
            var id = $(c).attr('id');
            $(c).attr('id', null);
            var src = $('<div>').append($(c).clone()).html();
            templates[id] = src;
          });

          function render(type, params, nondraggable) {
            if(!params['type']) {
              params['type'] = type;
            }
            var src = templates[type];
            if(!src) {
              console.log("ERROR: Unable to find template:", type)
            }
            for(var key in params) {
              src = src.replace('{{' + key + '}}', params[key]);
            }
            var el = $.parseHTML(src)[0];
            el.attrs = params;
            if(params['parent']) {
              var parent = components[params['parent']];
              $(parent).find('.children').append(el);
            } else {
              canvas.append(el);
            }
            if(!nondraggable) {
              j.draggable(el);
            }
            return el;
          }

          function connect(el1, el2, invisible) {
            j.connect({
              source: el1, target: el2,
              anchor:[ "Continuous", {
                faces:["top", "bottom", "left", "right"]
              }],
              overlays: [
                  [ "PlainArrow", { location: 1 }, { cssClass: invisible ? "invisible" : "" } ],
                  [ "Label", { cssClass: "TODO" } ]
              ],
              cssClass: invisible ? "invisible" : ""
            });
          }

          function layout() {

            // construct dagre graph from JsPlumb graph
            var g = new dagre.graphlib.Graph();
            g.setGraph({
              'rankdir': 'LR',
              'nodesep': 30,
              'ranksep': 70
            });
            g.setDefaultEdgeLabel(function() { return {}; });
            var nodes = $(".plumb");
            nodes.each(function(i,n) {
                var n = nodes[i];
                var width = $(n).width();
                var height = $(n).height();
                g.setNode(n.id, { width: width, height: height });
            });
            var edges = j.getAllConnections();
            for (var i = 0; i < edges.length; i++) {
                var c = edges[i];
                g.setEdge(c.source.id, c.target.id );
            }
            dagre.layout(g);
            // Applying the calculated layout
            g.nodes().forEach(function(v) {
              $("#" + v).css("left", marginLeft + (g.node(v).x - ($("#" + v).width() / 2)) + "px");
              $("#" + v).css("top", marginTop + (g.node(v).y - ($("#" + v).height() / 2)) + "px");
            });
          }

          function isConnected(node, edges) {
            for(var i = 0; i < edges.length; i ++) {
              var edge = edges[i];
              if(edge.target == node.id || edge.source == node.id) {
                return true;
              }
            }
            return false;
          }

          var hideDisconnected = $scope.settings.hideDisconnected;
          graphData.nodes.forEach(function(node) {
            if(!hideDisconnected || node.parent || isConnected(node, graphData.edges)) {
              var el = render(node.type, node);
              components[node.id] = el;
            }
          });
          graphData.edges.forEach(function(edge) {
            var src = components[edge.source];
            var tgt = components[edge.target];
            connect(src, tgt);
          });

          function repaint () {
            /* repainting a single time does not seem to work */
            setTimeout(function(){ for(var i = 0; i < 5; i ++) { j.repaintEverything(); } });
          }


          // var m1 = render('micros', {name: 'Feeder 1'});
          // var k1 = render('kinesis', {'name': 'Kinesis 1'});
          // var ks1 = render('kinesis_shard', {'name': 'Shard 1'}, true);
          // var ks2 = render('kinesis_shard', {'name': 'Shard 2'}, true);
          // $(k1).select('.shards').append(ks1);
          // $(k1).select('.shards').append(ks2);
          // var l1 = render('lambda', {'name': 'Lambda (raw)'});
          // var l2 = render('lambda', {'name': 'Lambda (conformed)'});
          // var b1 = render('s3', {'name': 'Raw Bucket'});
          // var b2 = render('s3', {'name': 'Conformed Bucket'});
          // var e1 = render('es', {'name': 'Search Index'});

          // connect(m1, ks1);
          // connect(m1, ks2);
          // connect(k1, l1, true);
          // connect(ks1, l1);
          // connect(ks2, l1);
          // connect(l1, b1);
          // connect(b1, l2);
          // connect(l2, b2);
          // connect(l2, e1);

          layout();

          $scope.selection.obj = null;
          $(".selectnode").mousedown(function(e) {
            $(".selected").removeClass("selected");
            var node = $(e.target).closest('.layoutnode').get(0);
            $(node).addClass("selected");
            var selectionNode = $(e.target).closest('.selectnode').get(0);
            $(selectionNode).addClass("selected");
            $scope.selection.obj = selectionNode;
            $scope.$parent.$parent.$apply();
          });

          $("#graph").mousedown(function(e) {
            $(".selected").removeClass("selected");
            $scope.selection.obj = null;
            $scope.$parent.$parent.$apply();
          });

          $(".show_hide").click(function(e){
            $(e.target).closest(".layoutnode").find(".children").toggle();
            var val = $(e.target).text();
            if(val.indexOf('show') >= 0) {
              val = val.replace('show', 'hide');
            } else {
              val = val.replace('hide', 'show');
            }
            $(e.target).text(val);
            repaint();
          });

          repaint();

        });

      });

      return;
    };

    $scope.actions.loadGraph = function() {
      graphData = null;
      client.then(function(client) {
        $scope.loading = true;
        $scope.status = null;

        var params = {
          nameFilter: $scope.settings.nameFilter
        };
        client.default.getGraph({request: params}).then(function(obj) {
          $scope.loading = false;
          graphData = obj.obj
          drawGraph();
          $scope.$apply();
        }, function(err) {
          $scope.loading = false;
          $scope.status = "An error has occurred, could not load data from the service.";
          $scope.$apply();
        });

        $scope.$apply();
      });
    };

    /* re-draw graph on settings change */
    $scope.$watch('settings.hideDisconnected', function(newValue) {
      $scope.selection.obj = null;
      drawGraph();
    });

    $scope.actions.loadGraph();

  });

})();
