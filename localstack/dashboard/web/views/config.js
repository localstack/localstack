(function () {
  'use strict';

  var app = angular.module('app');

  app.controller('configCtrl', function($scope, restClient) {

    var client = restClient;

    var setConfigData = function(config) {
      $scope.$apply(function(){
        $scope.config = config.config;
      });
    };

    $scope.load = function() {
      client.then(function(client) {
        $scope.loading = true;
        client.default.getConfig().then(function(obj) {
          $scope.loading = false;
          setConfigData(obj.obj);
        }, function(err) {
          $scope.loading = false;
          console.log(err);
        });
      });
    };

    $scope.save = function() {
      client.then(function(client) {
        /* load config */
        client.default.setConfig({config:$scope.config}).then(function(obj) {
          setConfigData(obj.obj);
        }, function(err) {
          console.log(err);
        });
      });
    };

    $scope.load();

  });

})();