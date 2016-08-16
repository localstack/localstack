(function () {
  'use strict'

  var app = angular.module('app');

  app.controller('infraDetailsCtrl', function($scope, appConfig, restClient) {

	var client = restClient;
	$scope.state.kinesis = {
		data: {}
	};
	$scope.state.lambda = {
		data: {}
	};

    var codeDialog = $scope.state.lambda.dialog = function(title, text, callback, cancelCallback) {
		codeDialog.title = title;
		codeDialog.text = text;
		codeDialog.callback = callback;
		codeDialog.visible = true;
		codeDialog.ok = function() {
			codeDialog.visible = false;
			if(callback) callback();
		};
		codeDialog.cancel = function() {
			codeDialog.visible = false;
			if(cancelCallback) cancelCallback();
		};
    };

	$scope.showLambdaCode = function() {
		client.then(function(client) {
			$scope.state.lambda.loading = true;

			var attrs = $scope.selection.obj.attrs;
			var params = {
				functionName: attrs.name
			};
			$scope.state.lambda.data[attrs.arn] = [];

			client.default.getLambdaCode(params).then(function(obj) {
				console.log(obj);
				$scope.state.lambda.loading = false;
				$scope.state.lambda.data[attrs.arn] = obj.obj;
				$scope.state.lambda.dialog();
				$scope.$apply();
			}, function(err) {
				$scope.state.lambda.loading = false;
				$scope.status = "An error has occurred, could not load data from the service.";
				$scope.$apply();
			});

			$scope.$apply();
		});
	};

  	$scope.getKinesisEvents = function() {

  		client.then(function(client) {
			$scope.state.kinesis.loading = true;

			var attrs = $scope.selection.obj.attrs;
			if(!attrs.dataKey) {
				attrs.dataKey = attrs.streamName + ":" + attrs.arn
			}
			var params = {
				streamName: attrs.streamName,
				shardId: attrs.arn
			};
			$scope.state.kinesis.data[attrs.dataKey] = [];

			client.default.getKinesisEvents(params).then(function(obj) {
				$scope.state.kinesis.loading = false;
				$scope.state.kinesis.data[attrs.dataKey] = obj.obj.events;
				$scope.$apply();
			}, function(err) {
				$scope.state.kinesis.loading = false;
				$scope.status = "An error has occurred, could not load data from the service.";
				$scope.$apply();
			});

			$scope.$apply();
		});
  	};

  });

})();
