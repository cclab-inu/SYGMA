-- DeathStarBench Hotel Reservation mix for wrk/wrk2.
-- This copy removes the unavailable LuaSocket dependency, uses relative URLs
-- so the CLI endpoint is authoritative, and fixes reserve()'s missing lat/lon.

local address = tostring({})
local hex = string.match(address, "0x(%x+)") or "0"
math.randomseed(os.time() + (tonumber(hex, 16) % 1000000))
math.random(); math.random(); math.random()

local function get_user()
  local id = math.random(0, 500)
  local username = "Cornell_" .. tostring(id)
  return username, string.rep(tostring(id), 10)
end

local function dates()
  local in_day = math.random(9, 23)
  local out_day = math.random(in_day + 1, 24)
  return string.format("2015-04-%02d", in_day), string.format("2015-04-%02d", out_day)
end

local function location()
  local lat = 38.0235 + (math.random(0, 481) - 240.5) / 1000.0
  local lon = -122.095 + (math.random(0, 325) - 157.0) / 1000.0
  return lat, lon
end

local function search_hotel()
  local in_date, out_date = dates()
  local lat, lon = location()
  local path = string.format(
    "/hotels?inDate=%s&outDate=%s&lat=%s&lon=%s",
    in_date, out_date, tostring(lat), tostring(lon))
  return wrk.format("GET", path)
end

local function recommend()
  local coin = math.random()
  local requirement = coin < 0.33 and "dis" or (coin < 0.66 and "rate" or "price")
  local lat, lon = location()
  local path = string.format(
    "/recommendations?require=%s&lat=%s&lon=%s",
    requirement, tostring(lat), tostring(lon))
  return wrk.format("GET", path)
end

local function reserve()
  local in_date, out_date = dates()
  local lat, lon = location()
  local hotel_id = tostring(math.random(1, 80))
  local username, password = get_user()
  local path = string.format(
    "/reservation?inDate=%s&outDate=%s&lat=%s&lon=%s" ..
    "&hotelId=%s&customerName=%s&username=%s&password=%s&number=1",
    in_date, out_date, tostring(lat), tostring(lon), hotel_id,
    username, username, password)
  return wrk.format("POST", path)
end

local function user_login()
  local username, password = get_user()
  return wrk.format(
    "POST", "/user?username=" .. username .. "&password=" .. password)
end

request = function()
  local coin = math.random()
  if coin < 0.60 then
    return search_hotel()
  elseif coin < 0.99 then
    return recommend()
  elseif coin < 0.995 then
    return user_login()
  end
  return reserve()
end
