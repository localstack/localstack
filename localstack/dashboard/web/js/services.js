(function () {
  'use strict';

  var app = angular.module('app');

  app.factory('appConfig', function(restClient) {
    var client = restClient;
    return {
      extractConfigValue: function(key, configs) {
        var result = null;
        configs.forEach(function(config) {
          if(config.key == key) {
            result = config.value;
          }
        });
        return result;
      },
      injectConfigValue: function(key, value, configs) {
        configs.forEach(function(config) {
          if(config.key == key) {
            config.value = value;
          }
        });
        return configs;
      },
      getConfigValue: function(key, configs) {
        if(configs)
          return this.extractConfigValue(key, configs);
        var self = this;
        return this.getConfig(function(configs) {
          var result = self.extractConfigValue(key, configs);
          return result;
        });
      },
      setConfigValue: function(key, value, configs) {
        if(configs) {
          this.injectConfigValue(key, value, configs);
          return setConfig(configs);
        }
        var self = this;
        return this.getConfig(function(configs) {
          self.injectConfigValue(key, value, configs);
          return self.setConfig(configs);
        });
      },
      getConfig: function(callback) {
        return client.then(function(client) {
          return client.default.getConfig().then(function(config) {
            config = config.obj.config;
            if(callback)
              return callback(config);
            return config;
          });
        });
      },
      setConfig: function(config, callback) {
        return client.then(function(client) {
          return client.default.setConfig({config:config}).then(function(config) {
            config = config.obj.config;
            if(callback)
              return callback(config);
            return config;
          });
        });
      }
    };
  });

}());