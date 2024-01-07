function main() {
	var resolver = new ApiResolver('objc');//创建已加载Object-C类方法的API查找器
	var matches = resolver.enumerateMatchesSync("-[AFSecurityPolicy evaluateServerTrust:forDomain:]");//查找evaluateServerTrust:forDomain函数，返回数组类型
	if (matches.lenght == 0) {
		console.log("\n[E] -[AFSecurityPolicy evaluateServerTrust:forDomain:] is not found!\n");
		return;
	}
	Interceptor.attach(ptr(matches[0]["address"]),{
			onLeave: function(retval) {
				console.log("[I] -[AFSecurityPolicy evaluateServerTrust:forDomain:] hits!");
				retval.replace(1);//将返回值修改为1
			}
		}
	);
	console.log("[I] -[AFSecurityPolicy evaluateServerTrust:forDomain:] is hooked!\n")
}

main();
