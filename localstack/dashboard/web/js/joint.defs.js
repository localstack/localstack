(function () {

	// joint.shapes.aws1 = {};

	// joint.shapes.aws1.Kinesis = joint.dia.Element.extend({

	//	 markup: '<g class="rotatable"><g class="scalable"><rect class="card"/><image/></g><text class="rank"/><text class="name"/></g>',

	//	 defaults: joint.util.deepSupplement({

	//		 type: 'aws1.Kinesis',
	//		 size: { width: 180, height: 70 },
	//		 attrs: {

	//			 rect: { width: 170, height: 60 },

	//			 '.card': {
	//				 fill: '#FFFFFF', stroke: '#000000', 'stroke-width': 2,
	//				 'pointer-events': 'visiblePainted', rx: 10, ry: 10
	//			 },

	//			 image: {
	//				 width: 48, height: 48,
	//				 ref: '.card', 'ref-x': 10, 'ref-y': 5
	//			 },

	//			 '.rank': {
	//				 'text-decoration': 'underline',
	//				 ref: '.card', 'ref-x': 0.9, 'ref-y': 0.2,
	//				 'font-family': 'Courier New', 'font-size': 14,
	//				 'text-anchor': 'end'
	//			 },

	//			 '.name': {
	//				 'font-weight': '800',
	//				 ref: '.card', 'ref-x': 0.9, 'ref-y': 0.6,
	//				 'font-family': 'Courier New', 'font-size': 14,
	//				 'text-anchor': 'end'
	//			 }
	//		 }
	//	 }, joint.dia.Element.prototype.defaults)
	// });

	// joint.shapes.aws1.KinesisShard = joint.dia.Element.extend({

	//	 markup: '<g class="rotatable"><g class="scalable"><rect class="card"/><text class="name"/></g></g>',

	//	 defaults: joint.util.deepSupplement({

	//		 type: 'aws1.KinesisShard',
	//		 size: { width: 150, height: 50 },
	//		 attrs: {

	//			 rect: { width: 150, height: 50 },

	//			 '.card': {
	//				 fill: '#FFFFFF', stroke: '#000000', 'stroke-width': 2,
	//				 'pointer-events': 'visiblePainted', rx: 10, ry: 10
	//			 },

	//			 '.name': {
	//				 'font-weight': '800',
	//				 ref: '.card', 'ref-x': 0.9, 'ref-y': 0.6,
	//				 'font-family': 'Courier New', 'font-size': 14,
	//				 'text-anchor': 'end'
	//			 }
	//		 }
	//	 }, joint.dia.Element.prototype.defaults)
	// });

	// joint.shapes.aws1.Arrow = joint.dia.Link.extend({

	//	 defaults: {
	//		 type: 'aws1.Arrow',
	//		 source: { selector: '.card' }, target: { selector: '.card' },
	//		 attrs: { '.connection': { stroke: '#585858', 'stroke-width': 3 }},
	//		 z: -1
	//	 }
	// });



	joint.shapes.aws2 = {};

	joint.shapes.aws2.Model = joint.shapes.basic.Generic.extend(_.extend({}, joint.shapes.basic.PortsModelInterface, {

		markup: '<g class="rotatable"><g class="scalable"><rect class="body"/></g><text class="label"/><g class="inPorts"/><g class="outPorts"/></g>',
		portMarkup: '<g class="port port<%= id %>"><circle class="port-body"/><text class="port-label"/></g>',

		defaults: joint.util.deepSupplement({

			type: 'aws2.Model',
			size: { width: 1, height: 1 },

			inPorts: [],
			outPorts: [],

			attrs: {
				'.': { magnet: false },
				'.body': {
					width: 150,
					height: 250,
					stroke: '#000000'
				},
				'.port-body': {
					r: 10,
					magnet: true,
					stroke: '#000000'
				},
				text: {
					'pointer-events': 'none'
				},
				'.label': { text: 'Model', 'ref-x': .5, 'ref-y': 10, ref: '.body', 'text-anchor': 'middle', fill: '#000000' },
				'.inPorts .port-label': { x:-15, dy: 4, 'text-anchor': 'end', fill: '#000000' },
				'.outPorts .port-label':{ x: 15, dy: 4, fill: '#000000' }
			}

		}, joint.shapes.basic.Generic.prototype.defaults),

		getPortAttrs: function(portName, index, total, selector, type) {

			var attrs = {};

			var portClass = 'port' + index;
			var portSelector = selector + '>.' + portClass;
			var portLabelSelector = portSelector + '>.port-label';
			var portBodySelector = portSelector + '>.port-body';

			attrs[portLabelSelector] = { text: portName };
			attrs[portBodySelector] = { port: { id: portName || _.uniqueId(type) , type: type } };
			attrs[portSelector] = { ref: '.body', 'ref-y': (index + 0.5) * (1 / total) };

			if (selector === '.outPorts') { attrs[portSelector]['ref-dx'] = 0; }

			return attrs;
		}
	}));


	joint.shapes.aws2.Atomic = joint.shapes.aws2.Model.extend({

		defaults: joint.util.deepSupplement({

			type: 'aws2.Atomic',
			size: { width: 80, height: 80 },
			attrs: {
				'.body': { fill: 'salmon', r: 10 },
				'.label': { text: 'Atomic' },
				'.inPorts .port-body': { fill: 'PaleGreen' },
				'.outPorts .port-body': { fill: 'Tomato' }
			}

		}, joint.shapes.aws2.Model.prototype.defaults)

	});

	joint.shapes.aws2.Coupled = joint.shapes.aws2.Model.extend({

		defaults: joint.util.deepSupplement({

			type: 'aws2.Coupled',
			size: { width: 200, height: 300 },
			attrs: {
				'.body': { fill: 'seaGreen' },
				'.label': { text: 'Coupled' },
				'.inPorts .port-body': { fill: 'PaleGreen' },
				'.outPorts .port-body': { fill: 'Tomato' }
			}

		}, joint.shapes.aws2.Model.prototype.defaults)
	});

	joint.shapes.aws2.Kinesis = joint.shapes.aws2.Coupled;

	joint.shapes.aws2.KinesisShard = joint.shapes.aws2.Atomic;

	joint.shapes.aws2.Link = joint.dia.Link.extend({

		defaults: {
			type: 'aws2.Link',
			attrs: { '.connection' : { 'stroke-width' :	2 }}
		}
	});

	joint.shapes.aws2.ModelView = joint.dia.ElementView.extend(joint.shapes.basic.PortsViewInterface);
	joint.shapes.aws2.AtomicView = joint.shapes.aws2.ModelView;
	joint.shapes.aws2.CoupledView = joint.shapes.aws2.ModelView;


	/* apply extras to the graph */

	joint.applyExtras = function(graph, paper, params) {
		if(!params) params = {};

		/* returnestrict children to parent's bounding box*/
		graph.on('change:position', function(cell, newPosition, opt) {
			var parentId = cell.get('parent');
			if (params.limitChildToParent && parentId) {
				var parent = graph.getCell(parentId);
				var parentBbox = parent.getBBox();
				var cellBbox = cell.getBBox();
				if (parentBbox.containsPoint(cellBbox.origin()) &&
					parentBbox.containsPoint(cellBbox.topRight()) &&
					parentBbox.containsPoint(cellBbox.corner()) &&
					parentBbox.containsPoint(cellBbox.bottomLeft())) {
					return;
				}
				cell.set('position', cell.previous('position'));
			}
			if (params.extendParent && !opt.skipParentHandler) {
				if (cell.get('embeds') && cell.get('embeds').length) {
					// If we're manipulating a parent element, let's store
					// it's original position to a special property so that
					// we can shrink the parent element back while manipulating
					// its children.
					cell.set('originalPosition', cell.get('position'));
				}
				
				var parentId = cell.get('parent');
				if (!parentId) return;

				var parent = graph.getCell(parentId);
				var parentBbox = parent.getBBox();

				if (!parent.get('originalPosition')) parent.set('originalPosition', parent.get('position'));
				if (!parent.get('originalSize')) parent.set('originalSize', parent.get('size'));
				
				var originalPosition = parent.get('originalPosition');
				var originalSize = parent.get('originalSize');
				
				var newX = originalPosition.x;
				var newY = originalPosition.y;
				var newCornerX = originalPosition.x + originalSize.width;
				var newCornerY = originalPosition.y + originalSize.height;
				
				_.each(parent.getEmbeddedCells(), function(child) {

					var childBbox = child.getBBox();
					
					if (childBbox.x < newX) { newX = childBbox.x; }
					if (childBbox.y < newY) { newY = childBbox.y; }
					if (childBbox.corner().x > newCornerX) { newCornerX = childBbox.corner().x; }
					if (childBbox.corner().y > newCornerY) { newCornerY = childBbox.corner().y; }
				});

				// Note that we also pass a flag so that we know we shouldn't adjust the
				// `originalPosition` and `originalSize` in our handlers as a reaction
				// on the following `set()` call.
				parent.set({
					position: { x: newX, y: newY },
					size: { width: newCornerX - newX, height: newCornerY - newY }
				}, { skipParentHandler: true });
			}
		});

		joint.layout.DirectedGraph.layout(graph, {
		    nodeSep: 50,
		    edgeSep: 80,
		    rankDir: "LR",
			clusterPadding: { top: 30, left: 10, right: 10, bottom: 10 }
		});

		/* add scrollbars and zooming */
		$(paper.el).on('mousewheel', function(event) {
			// console.log(V(paper.viewport).scale())
		 //    var oldScale = V(paper.viewport).scale().sx;
		 //    var newScale = oldScale + event.originalEvent.deltaY/100;
		 //    console.log(oldScale, newScale)
		 //    var beta = oldScale/newScale;
		 //    //console.log(event);
		 //    var mouseX = event.clientX;
		 //    var mouseY = event.clientY;
		 //    var mouseLocal = V(paper.viewport).toLocalPoint(mouseX, mouseY);
		 //    var p = {x: mouseLocal.x, y: mouseLocal.y};
		 //    console.log(p);
		 //    ax = p.x - (p.x * beta);
		 //    ay = p.y - (p.y * beta);
		 //    console.log(newScale, newScale, ax, ay)
		 //    paper.scale(newScale, newScale);

		 	event.preventDefault();
		    event = event.originalEvent;

		    var delta = Math.max(-1, Math.min(1, (event.wheelDelta || -event.detail))) / 50;
		    var offsetX = (event.offsetX || event.clientX - $(this).offset().left); // offsetX is not defined in FF
		    var offsetY = (event.offsetY || event.clientY - $(this).offset().top); // offsetY is not defined in FF
		    var p = offsetToLocalPoint(offsetX, offsetY);
		    var newScale = V(paper.viewport).scale().sx + delta; // the current paper scale changed by delta

		    if (newScale > 0.4 && newScale < 2) {
		        //paper.setOrigin(0, 0); // reset the previous viewport translation
		        paper.scale(
		        	newScale, newScale
		        	//, p.x, p.y
		        );
		    }
		});
		function offsetToLocalPoint(x, y) {
			return V(paper.viewport).toLocalPoint(x, y);

		    var svgPoint = paper.svg.createSVGPoint();
		    svgPoint.x = x;
		    svgPoint.y = y;
		    // Transform point into the viewport coordinate system.
		    var pointTransformed = svgPoint.matrixTransform(paper.viewport.getCTM().inverse());
		    return pointTransformed;
		}

		/* enable paper dragging */
		var dragStartPosition = null;
		paper.on('blank:pointerdown',
		    function(event, x, y) {
		        dragStartPosition = { x: x, y: y};
		    }
		);
		paper.on('cell:pointerup blank:pointerup', function(cellView, x, y) {
			dragStartPosition = undefined;
		    delete dragStartPosition;
		});
		$(paper.el).mousemove(function(event) {
	        if (dragStartPosition) {
	        	var dx = event.offsetX - dragStartPosition.x;
	        	var dy = event.offsetY - dragStartPosition.y;
	        	var newX = dx;
	        	var newY = dy;
	            paper.setOrigin(newX, newY);
	        }
	    });
	};

})();

