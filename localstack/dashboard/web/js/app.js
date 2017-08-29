(function () {
  'use strict';

  var app = angular.module('app', [
    'ui.router',
    'ngResource',
    'ngSanitize',
    'angularResizable',
    'tableSort',
    'ui.layout'
  ]);

  app.config(function($stateProvider, $urlRouterProvider) {

    $stateProvider.
    state('infra', {
      url: '/infra',
      templateUrl: 'views/infra.html',
      controller: 'infraCtrl'
    }).
    state('infra.graph', {
      url: '/graph',
      templateUrl: 'views/infra.graph.html',
      controller: 'graphCtrl'
    }).
    state('config', {
      url: '/config',
      templateUrl: 'views/config.html',
      controller: 'configCtrl'
    });

    $urlRouterProvider.otherwise('/infra');
  });

  app.factory('restClient', function($resource) {
    return new SwaggerClient({
      url: "//" + document.location.host + "/swagger.json",
      usePromise: true
    });
  });
}());
