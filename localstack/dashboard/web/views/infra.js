(function () {
  'use strict'

  var app = angular.module('app');

  app.controller('infraCtrl', function($scope, appConfig, restClient) {

    $scope.selection = {};
    $scope.actions = {};
    $scope.state = {};
    $scope.settings = {
    	hideDisconnected: true,
    	nameFilter: '(?!(segment-|aes-|.*zone-)).*'
    };

    $scope.trim = function(string, maxLength) {
      if(typeof maxLength == 'undefined') {
        maxLength = 80;
      }
      return string.length <= maxLength ?
            string : string.substring(0, maxLength - 3) + "...";
    }

    $scope.format_datetime = function(ms) {
      var a = new Date(parseInt(ms));
      //var months = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
      //var month = months[a.getMonth()];
      var month = a.getMonth() + 1;
      month = month < 10 ? '0' + month : month;
      var year = a.getFullYear();
      var date = a.getDate() < 10 ? '0' + a.getDate() : a.getDate();
      var hour = a.getHours() < 10 ? '0' + a.getHours() : a.getHours();
      var min = a.getMinutes() < 10 ? '0' + a.getMinutes() : a.getMinutes();
      var sec = a.getSeconds() < 10 ? '0' + a.getSeconds() : a.getSeconds();
      var time = year + '-' + month + '-' + date + ' ' + hour + ':' + min + ':' + sec ;
      return time;
    };

  });

})();
