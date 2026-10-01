local function counter(n)
  return function(add) n = n + (add or 1); return n, "middle", "tail" end
end
local a,b=counter(2),counter(10)
print(a(3)); print(b(false)); print(a(0))
local sum=0
for i=1,8 do if i%2==0 then sum=sum+i else sum=sum-i end end
local t=setmetatable({},{__index=function(_,key) return "key:"..key end})
print(sum,t.hello)
return a(7)
