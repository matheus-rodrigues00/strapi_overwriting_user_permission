"use strict";

module.exports = (plugin) => {
  plugin.controllers.auth.callback = async (ctx) => {
    const password = ctx.request.body.password;
    const email = ctx.request.body.identifier;
    return {
      email,
      password,
    };
  };
  // now the regsiter
  plugin.controllers.auth.register = async (ctx) => {
    const password = ctx.request.body.password;
    const email = ctx.request.body.email;
    const name = ctx.request.body.username;
    const username = ctx.request.body.username;
    return {
      email,
      name,
      username,
      password,
    };
  };
  return plugin;
};
