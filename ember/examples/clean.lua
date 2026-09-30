-- A normal server script: nothing here should be flagged.
local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")
local ReplicatedStorage = game:GetService("ReplicatedStorage")

local Config = require(ReplicatedStorage:WaitForChild("Config"))
local Signal = require(script.Parent.Signal)

local stats = {}

Players.PlayerAdded:Connect(function(player)
	stats[player.UserId] = { coins = Config.StartingCoins, joined = os.time() }
end)

Players.PlayerRemoving:Connect(function(player)
	local payload = HttpService:JSONEncode(stats[player.UserId])
	print(("[stats] %s left: %s"):format(player.Name, payload))
	stats[player.UserId] = nil
end)

return Signal
