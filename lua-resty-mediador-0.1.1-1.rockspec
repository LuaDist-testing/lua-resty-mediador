-- This file was automatically generated for the LuaDist project.

package = "lua-resty-mediador"
version = "0.1.1-1"

description = {
  summary  = "Mediador, determine address of proxied request and IP handling",
  homepage = "https://github.com/Mashape/lua-resty-mediador",
  license  = "MIT"
}

-- LuaDist source
source = {
  tag = "0.1.1-1",
  url = "git://github.com/LuaDist-testing/lua-resty-mediador.git"
}
-- Original source
-- source = {
--   url    = "git://github.com/mashape/lua-resty-mediador.git",
--   branch = "v0.1.1"
-- }

dependencies = {
    "luabitop"
}

build = {
  type    = "builtin",
  modules = {
    ["resty.mediador.ip"]    = "lib/resty/mediador/ip.lua",
    ["resty.mediador.proxy"] = "lib/resty/mediador/proxy.lua"
  }
}