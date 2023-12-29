var NSData = ObjC.classes.NSData;
var NSString = ObjC.classes.NSString;

function unicode2str(str) {
    var ret = "";
    var ustr = "";
 
    for (var i = 0; i < str.length; i++) {
        var code = str.charCodeAt(i);
        var code16 = code.toString(16);
        if (code < 0xf) {
            ustr = "\\u" + "000" + code16;
        } else if(code < 0xff){
            ustr = "\\u" + "00" + code16;
        } else if(code < 0xfff){
            ustr = "\\u" + "0" + code16;
        } else {
            ustr = "\\u" + code16;
        }  
        ret += ustr;
    }
    return ret;
}

/* JavaScript String -> NSString */
function str(s) {
    return Memory.allocUtf8String(s);
}

function nsstr(str) {
    return ObjC.classes.NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}

/* NSString -> NSData */
function nsstr2nsdata(nsstr) {
    return nsstr.dataUsingEncoding_(4);
}

/* NSData -> NSString */
function nsdata2nsstr(nsdata) {
    return ObjC.classes.NSString.alloc().initWithData_encoding_(nsdata, 4);
}

/* Print Native Callstack */
function callstack() {
    console.log(Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n") + "\n");
}

function callstack_() {
	console.log(ObjC.classes.NSThread.callStackSymbols().toString());
}

/* c function wrapper */
function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

function modload(modpath) {
    var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);
    dlopen(str(modpath), 1);
}

function getscreensize() {
    var UIScreen = ObjC.classes.UIScreen;
    return UIScreen.mainScreen().bounds()[1];
}

function click(x, y) {
    // https://github.com/zjjno/PTFakeTouchDemo.git 编译为dylib
    modload("/Library/MobileSubstrate/DynamicLibraries/PTFakeTouch.dylib")
    var touchxy = getExportFunction("f", "touchxy", "void", ["int", "int"]);
    touchxy(x, y);
}

function _utf8_encode(string) {
    string = string.replace(/\r\n/g, "\n");
    var utftext = "";
    for (var n = 0; n < string.length; n++) {
        var c = string.charCodeAt(n);
        if (c < 128) {
            utftext += String.fromCharCode(c);
        } else if ((c > 127) && (c < 2048)) {
            utftext += String.fromCharCode((c >> 6) | 192);
            utftext += String.fromCharCode((c & 63) | 128);
        } else {
            utftext += String.fromCharCode((c >> 12) | 224);
            utftext += String.fromCharCode(((c >> 6) & 63) | 128);
            utftext += String.fromCharCode((c & 63) | 128);
        }
    }
    return utftext;
}

// 获取keychain数据
function getkeychain() {
    var NSMutableDictionary=ObjC.classes.NSMutableDictionary;
    var kCFBooleanTrue = ObjC.Object(getExportFunction("d", "kCFBooleanTrue"));
    var kSecReturnAttributes = ObjC.Object(getExportFunction("d", "kSecReturnAttributes"));
    var kSecMatchLimitAll = ObjC.Object(getExportFunction("d", "kSecMatchLimitAll"));
    var kSecMatchLimit = ObjC.Object(getExportFunction("d", "kSecMatchLimit"));
    var kSecClassGenericPassword = ObjC.Object(getExportFunction("d", "kSecClassGenericPassword"));
    var kSecClassInternetPassword = ObjC.Object(getExportFunction("d", "kSecClassInternetPassword"));
    var kSecClassCertificate = ObjC.Object(getExportFunction("d", "kSecClassCertificate"));
    var kSecClassKey = ObjC.Object(getExportFunction("d", "kSecClassKey"));
    var kSecClassIdentity = ObjC.Object(getExportFunction("d", "kSecClassIdentity"));
    var kSecClass = ObjC.Object(getExportFunction("d","kSecClass"));

    var query = NSMutableDictionary.alloc().init();
    var SecItemCopyMatching = getExportFunction("f", "SecItemCopyMatching", "int", ["pointer", "pointer"]);
    [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey, 
        kSecClassIdentity].forEach(function(secItemClass) {
            query.setObject_forKey_(kCFBooleanTrue, kSecReturnAttributes);
            query.setObject_forKey_(kSecMatchLimitAll, kSecMatchLimit);
            query.setObject_forKey_(secItemClass, kSecClass);
            var result = Memory.alloc(8);
            Memory.writePointer(result, ptr("0"));
            SecItemCopyMatching(query.handle, result);
            var pt = Memory.readPointer(result);
            if (!pt.isNull()) {
                console.log(ObjC.Object(pt).toString());
            }
        }
    )
}

function cleankeychain() {
    var NSMutableDictionary=ObjC.classes.NSMutableDictionary;
    var kSecClassGenericPassword = ObjC.Object(getExportFunction("d", "kSecClassGenericPassword"));
    var kSecClassInternetPassword = ObjC.Object(getExportFunction("d", "kSecClassInternetPassword"));
    var kSecClassCertificate = ObjC.Object(getExportFunction("d", "kSecClassCertificate"));
    var kSecClassKey = ObjC.Object(getExportFunction("d", "kSecClassKey"));
    var kSecClassIdentity = ObjC.Object(getExportFunction("d", "kSecClassIdentity"));
    var kSecClass = ObjC.Object(getExportFunction("d","kSecClass"));
    var SecItemDelete = getExportFunction("f", "SecItemDelete", "int", ["pointer"]);
    var query = NSMutableDictionary.alloc().init();
    [kSecClassGenericPassword, kSecClassInternetPassword, kSecClassCertificate, kSecClassKey, 
        kSecClassIdentity].forEach(function(secItemClass) {
            query.setObject_forKey_(secItemClass, kSecClass);
            SecItemDelete(query.handle);
        }
    )
}

/* Base64 Encode */
function base64(input) {
    var _keyStr = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    var output = "";
    var chr1, chr2, chr3, enc1, enc2, enc3, enc4;
    var i = 0;
    input = _utf8_encode(input);
    while (i < input.length) {
        chr1 = input.charCodeAt(i++);
        chr2 = input.charCodeAt(i++);
        chr3 = input.charCodeAt(i++);
        enc1 = chr1 >> 2;
        enc2 = ((chr1 & 3) << 4) | (chr2 >> 4);
        enc3 = ((chr2 & 15) << 2) | (chr3 >> 6);
        enc4 = chr3 & 63;
        if (isNaN(chr2)) {
            enc3 = enc4 = 64;
        } else if (isNaN(chr3)) {
            enc4 = 64;
        }
        output = output + _keyStr.charAt(enc1) + _keyStr.charAt(enc2) + _keyStr.charAt(enc3) + _keyStr.charAt(enc4);
    }
    return output;
}

/* Get KeyBlockSize from SecKeyRef */
function getPubkeyBlocksize(seckeyref) {
    var SecKeyGetBlockSize = new NativeFunction(Module.findExportByName(null, "SecKeyGetBlockSize"), "int", ["pointer"]);
    return SecKeyGetBlockSize(seckeyref);
}

/* Get RSA Public Key from SecKeyRef */
function getPubkeyFromKeyref(seckeyref) {
    var seckeyref = ObjC.classes.CBKeyStore.getConsultPasswordPublicKey();
    var publicTag = nsstr2nsdata(nsstr("com.your.company.publickey"));
    var queryPublicKey = ObjC.classes.NSMutableDictionary.alloc().init();
    var kSecClassKey = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecClassKey")));
    var kSecAttrApplicationTag = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrApplicationTag")));
    var kSecAttrKeyTypeRSA = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrKeyTypeRSA")));
    var kSecAttrKeyType = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecAttrKeyType")));
    var kSecValueRef = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecValueRef")));
    var kSecReturnData = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecReturnData")));
    var kSecClass = ObjC.Object(Memory.readPointer(Module.findExportByName(null, "kSecClass")));
    var yes = ObjC.classes.NSNumber.numberWithBool_(1);
    queryPublicKey.setObject_forKey_(kSecClassKey, kSecClass);
    queryPublicKey.setObject_forKey_(publicTag, kSecAttrApplicationTag);
    queryPublicKey.setObject_forKey_(kSecAttrKeyTypeRSA, kSecAttrKeyType);
    var attributes = queryPublicKey.mutableCopy();
    attributes.setObject_forKey_(seckeyref, kSecValueRef);
    attributes.setObject_forKey_(yes, kSecReturnData);
    var publicKeyBits = Memory.alloc(Process.pointerSize);
    Memory.writePointer(publicKeyBits, ptr("0"));
    var SecItemAdd = new NativeFunction(Module.findExportByName(null, "SecItemAdd"), "int", ["pointer", "pointer"]);
    var SecItemDelete = new NativeFunction(Module.findExportByName(null, "SecItemDelete"), "int", ["pointer"]);
    SecItemDelete(queryPublicKey.handle);
    var sanityCheck = SecItemAdd(attributes.handle, publicKeyBits);
    if (sanityCheck == 0) console.log("success");
    else console.log("failure");
    return ObjC.Object(Memory.readPointer(publicKeyBits));
}

/* Get all modules */
function getmodule() {
	var modules = Process.enumerateModulesSync();
	return modules.map(function (item) {
		return item['path'];
	});
}

/* Get all class in module */
function getmoduleclass(module) {
	if (module == null) {
		module = Process.enumerateModulesSync()[0]['path'];
	}
	var pcount = Memory.alloc(4);
	Memory.writeU32(pcount, 0);
	var objc_copyClassNamesForImage = new NativeFunction(Module.findExportByName(null, "objc_copyClassNamesForImage"), "pointer", ["pointer", "pointer"]);
	var classptrarr = objc_copyClassNamesForImage(Memory.allocUtf8String(module), pcount);
	var count = Memory.readU32(pcount);
	var result = Array();
	for (var i = 0; i < count; i++) {
		var classptr = Memory.readPointer(classptrarr.add(Process.pointerSize * i));
		result.push(Memory.readUtf8String(classptr));
	}
	return result;
}

function getclassmodule(classname) {
    var objc_getClass = new NativeFunction(Module.findExportByName(null, "objc_getClass"), "pointer", ["pointer"]);
    var class_getImageName = new NativeFunction(Module.findExportByName(null, "class_getImageName"), "pointer",
        ["pointer"]);
    var class_ = objc_getClass(Memory.allocUtf8String(classname));
    return Memory.readUtf8String(class_getImageName(class_));
}

function getsymbolmodule(symbolname) {
    var dladdr = new NativeFunction(Module.findExportByName(null, "dladdr"), "int", ["pointer", "pointer"]);
    var info = Memory.alloc(Process.pointerSize * 4);
    dladdr(Module.findExportByName(null, symbolname), info);
    return {
        "fname": Memory.readUtf8String(Memory.readPointer(info)),
        "fbase": Memory.readPointer(info.add(Process.pointerSize)),
        "sname": Memory.readUtf8String(Memory.readPointer(info.add(Process.pointerSize * 2))),
        "saddr": Memory.readPointer(info.add(Process.pointerSize * 3)),
    }
}

function getaddressmodule(address) {
    var dladdr = new NativeFunction(Module.findExportByName(null, "dladdr"), "int", ["pointer", "pointer"]);
    var info = Memory.alloc(Process.pointerSize * 4);
    dladdr(ptr(address), info);
    return {
        "fname": Memory.readUtf8String(Memory.readPointer(info)),
        "fbase": Memory.readPointer(info.add(Process.pointerSize)),
        "sname": Memory.readUtf8String(Memory.readPointer(info.add(Process.pointerSize * 2))),
        "saddr": Memory.readPointer(info.add(Process.pointerSize * 3)),
    }
}

function getfilename(path) {
    return path.substring(path.lastIndexOf("/") + 1);
}

/* Get Objective-C Method of class */
function getclassmethod(classname, base) {
    if (!base) base = ptr(0);
    var objc_getClass = new NativeFunction(Module.findExportByName(null, "objc_getClass"), "pointer", ["pointer"]);
    var objc_getMetaClass = new NativeFunction(Module.findExportByName(null, "objc_getMetaClass"), "pointer", ["pointer"]);
    var class_ = objc_getClass(Memory.allocUtf8String(classname));
    if (class_.isNull()) {
        console.log("class not found");
        return;
    }
    var metaclass_ = objc_getMetaClass(Memory.allocUtf8String(classname));
    var pcount = Memory.alloc(256);
    Memory.writeU32(pcount, 0);
    var class_copyMethodList = new NativeFunction(Module.findExportByName(null, "class_copyMethodList"), "pointer", ["pointer", "pointer"]);
    var method_getName = new NativeFunction(Module.findExportByName(null, "method_getName"), "pointer", ["pointer"]);
    var method_getImplementation = new NativeFunction(Module.findExportByName(null, "method_getImplementation"), "pointer", ["pointer"]);
    var methodptrarr = class_copyMethodList(class_, pcount);
    var count = Memory.readU32(pcount);
	var result = new Array();
    for (var i = 0; i < count; i++) {
        var method = Memory.readPointer(methodptrarr.add(Process.pointerSize * i));
        var name = Memory.readUtf8String(method_getName(method));
        var imp = method_getImplementation(method);
		result.push({"name": "-[" + classname + " " + name + "]", "imp":imp.sub(base)});
        //console.log("-[" + classname + " " + name + "] -> " + imp);
    }
	Memory.writeU32(pcount, 0);
	methodptrarr = class_copyMethodList(metaclass_, pcount);
    count = Memory.readU32(pcount);
    for (var i = 0; i < count; i++) {
        var method = Memory.readPointer(methodptrarr.add(Process.pointerSize * i));
        var name = Memory.readUtf8String(method_getName(method));
        var imp = method_getImplementation(method);
        var imp_mod = Process.findRangeByAddress(imp);
        if (!imp_mod.file || !imp_mod.file.path) {
            console.log("err:" + classname + " " + name);
            return;
        }
        var mod = getfilename(imp_mod.file.path);
		result.push({"name": "+[" + classname + " " + name + "]", "imp":imp.sub(base)});
        //console.log("+[" + classname + " " + name + "] -> " + imp);
    }
	return result;
}

// 强制过证书校验
function forcetrustcert() {
	Interceptor.replace(Module.findExportByName(null, 'SecTrustEvaluate'),
		new NativeCallback(function (trust, result) {
			Memory.writePointer(result, ptr('0x1'));
			 console.log('pass SecTrustEvaluate');
			return 0;
		}, 'int', ['pointer', 'pointer'])
	);
	/* 获取app路径下的可执行模块 hook存在以下方法的类
		- evaluateServerTrust:forDomain:
		- allowInvalidCertificates
		- shouldContinueWithInvalidCertificate
	*/
	var apppath = Process.enumerateModulesSync()[0]['path'];
	apppath = apppath.slice(0, apppath.lastIndexOf('/'));
	getmodule().forEach(function (module, i) {
		if (module.indexOf(apppath) != 0) return;
		getmoduleclass(module).forEach(function (classname, j) {
			getclassmethod(classname).forEach(function (methodinfo, k) {
				var name = methodinfo['name'];
				if (name == '- evaluateServerTrust:forDomain:' ||
						name == '- allowInvalidCertificates' ||
						name == '- shouldContinueWithInvalidCertificate') {
					console.log("forcetrustcert " + classname + " " + name);
					Interceptor.attach(methodinfo['imp'], {
						onEnter: function (args) {
							console.log("forcetrustcert " + classname + " " + name);
						},
						onLeave: function (retval) {
							retval.replace(ptr('0x1'));
						}
					});
				}
			});
		});
	});
}

// 随机字符串
function randomString(len) {
　　len = len || 32;
　　var $chars = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678';
　　var maxPos = $chars.length;
　　var pwd = '';
　　for (i = 0; i < len; i++) {
　　　　pwd += $chars.charAt(Math.floor(Math.random() * maxPos));
　　}
　　return pwd;
}

// 生成二进制NSData
function rawnsdata() {
	var buf = Memory.alloc(256);
	for (var i = 0; i < 256; i++) {
		Memory.writeU8(buf.add(i), i);
	}
	return ObjC.classes.NSData.dataWithBytes_length_(buf, 256);
}

function dump_alertview() {
    ObjC.chooseSync(ObjC.classes.UIAlertController).forEach(
        function(alertcontroller) {
            var actions = alertcontroller.actions();
            for (var i = 0; i < actions.count(); i++) {
                var action = actions.objectAtIndex_(i);
                var handler = action.handler();
                if (handler != null) handler = handler.handle;
                console.log(action.title(), handler);
            }
        }
    );
}

function get_object_method_address(object, action) {
    var class_getMethodImplementation = new NativeFunction(Module.findExportByName(null, "class_getMethodImplementation"), "pointer", ["pointer", "pointer"]);
    var imp = class_getMethodImplementation(object.class(), ObjC.selector(action));
    var mod = Process.getModuleByAddress(imp);
    return mod['name'] + '!' + imp.sub(mod['base'])
}   

function get_function_address(address) {
    address = ptr(address);
    var symbol = getaddressmodule(address);
    var sympath = symbol['fname'];
    var symname = "";
    if (sympath != null)
        symname = sympath.split('/')[sympath.split('/').length - 1];
    return symname + '!' + address.sub(symbol['fbase']);
}

// 遍历界面元素
function tranverse_view() { 
    var appCls = ObjC.classes["NSApplication"] || ObjC.classes["UIApplication"];
    var mainwin = appCls.sharedApplication().keyWindow();
    var arr = Array();
    function find_subviews_internal(view, depth) {
        if (view == null) {
            return;
        }
        var space = '';
        for (var i = 0; i < depth; i++) {
            space += '-';
        }
        var text = '';
        var ctrlname = view.class().toString();
        if (view.respondsToSelector_(ObjC.selector('text'))) {
            text = view.text()==null?"":view.text().toString();
        }
        var responder = '';
        var iter = true;
        if (view.respondsToSelector_(ObjC.selector('allTargets'))) {
            var targets = view.allTargets().allObjects();
			if (targets != null) {
				var targetcount = targets.count();
				var events = view.allControlEvents();
				for (var i = 0; i < targetcount; i++) {
					var target = targets.objectAtIndex_(i);
					var actions = view.actionsForTarget_forControlEvent_(target, events);
					if (actions != null) {
						var actioncount = actions.count();
						for (var j = 0; j < actioncount; j++) {
                            var clsname = target.class().toString();
                            var action = actions.objectAtIndex_(j).toString();
                            var addr = get_object_method_address(target, action)
							responder += '[' + clsname + ' ' + action + ']=' + addr + ',';
						}
					}
				}
			}
        }
        var msg = space + ctrlname + " " + view.handle;
        if (text.length > 0) {
            msg += "  => " + unicode2str(text);
        }
        if (responder != '') {
            msg += "  selectors= " + responder;
        }
        console.log((msg));
        if (view.respondsToSelector_(ObjC.selector('actions'))) {
            // UIAlertView
            iter = false;
            var actions = view.actions();
            var actioncount = actions.count();
            for (var j = 0; j < actioncount; j++) {
                var action = actions.objectAtIndex_(j);
                var title = action.title().UTF8String();
                if (action.handler() == null) {
                    console.log((space + '  action= ' + unicode2str(title)));
                } else {
                    var block = action.handler().handle;
                    var funcaddr = Memory.readPointer(block.add(Process.pointerSize * 2));
                    var types = action.handler().types;
                    var addr = get_function_address(funcaddr);
                    console.log((space + '  action= ' + unicode2str(title) + ' ' + types + ' ' + addr));
                }
            }
        }
        if (view.respondsToSelector_(ObjC.selector('gestureRecognizers'))) {
            var gestures = view.gestureRecognizers();
            if (gestures != null) {
                var gesturecount = gestures.count();
                for (var k = 0; k < gesturecount; k++) {
                    var gesture = gestures.objectAtIndex_(k);
                    var targets = ObjC.Object(gesture.handle.add(16).readPointer());
                    if (targets.handle.isNull()) {
                        continue;
                    }
                    var targetcount = targets.count();
                    for (var l = 0; l < targetcount; l++) {
                        var target = targets.objectAtIndex_(l);
                        var addr = get_function_address(target.action());
                        console.log(space + 'action', addr);
                    }
                }
            }
            
            /*for (var j = 0; j < gesturecount; j++) {
                var gesture = gestures.objectAtIndex_(j);

            }*/
        }
        var subviews = view.subviews();
		if (subviews != null && iter) {
			var subviewcount = subviews.count();
			for (var i = 0; i < subviewcount; i++) {
				var subview = subviews.objectAtIndex_(i);
				find_subviews_internal(subview, depth + 1);
			}
		}
    }

    find_subviews_internal(mainwin, 0);
}

function trace_view() {
    var UIApplication = ObjC.classes.UIApplication;
    Interceptor.attach(UIApplication["- sendAction:to:from:forEvent:"].implementation, {
        onEnter:function(args) {
            var action = Memory.readUtf8String(args[2]);
            var toobj = ObjC.Object(args[3]);
            var fromobj = ObjC.Object(args[4]);
            var event = ObjC.Object(args[5]);
            console.log('SendAction:' + action + ' to:' + toobj.toString() + 
          ' from:' + fromobj.toString() + ' forEvent:' + event.toString() + ']');
        }
    });
}

var O_RDONLY = 0;
var O_WRONLY = 1;
var O_RDWR = 2;
var O_CREAT = 512;

var SEEK_SET = 0;
var SEEK_CUR = 1;
var SEEK_END = 2;

var NSString = ObjC.classes.NSString;
var NSFileManager = ObjC.classes.NSFileManager;

function allocStr(str) {
    return Memory.allocUtf8String(str);
}

function getNSString(str) {
    return NSString.stringWithUTF8String_(Memory.allocUtf8String(str));
}

function getStr(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr);
}

function getStrSize(addr, size) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readUtf8String(addr, size);
}

function putStr(addr, str) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeUtf8String(addr, str);
}

function getByteArr(addr, l) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readByteArray(addr, l);
}

function getU8(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU8(addr);
}

function putU8(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU8(addr, n);
}

function getU16(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU16(addr);
}

function putU16(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU16(addr, n);
}

function getU32(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU32(addr);
}

function putU32(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU32(addr, n);
}

function getU64(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readU64(addr);
}

function putU64(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.writeU64(addr, n);
}

function getPt(addr) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    return Memory.readPointer(addr);
}

function putPt(addr, n) {
    if (typeof addr == "number") {
        addr = ptr(addr);
    }
    if (typeof n == "number") {
        n = ptr(n);
    }
    return Memory.writePointer(addr, n);
}

function malloc(size) {
    return Memory.alloc(size);
}

function getExportFunction(type, name, ret, args) {
    var nptr;
    nptr = Module.findExportByName(null, name);
    if (nptr === null) {
        console.log("cannot find " + name);
        return null;
    } else {
        if (type === "f") {
            var funclet = new NativeFunction(nptr, ret, args);
            if (typeof funclet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return funclet;
        } else if (type === "d") {
            var datalet = Memory.readPointer(nptr);
            if (typeof datalet === "undefined") {
                console.log("parse error " + name);
                return null;
            }
            return datalet;
        }
    }
}

function dumpMemory(addr, length) {
    console.log(hexdump(Memory.readByteArray(addr, length), {
        offset: 0,
        length: length,
        header: true,
        ansi: true
    }));
}

var NSSearchPathForDirectoriesInDomains = getExportFunction("f", "NSSearchPathForDirectoriesInDomains", "pointer", ["int", "int", "int"]);
var wrapper_open = getExportFunction("f", "open", "int", ["pointer", "int", "int"]);
var read = getExportFunction("f", "read", "int", ["int", "pointer", "int"]);
var write = getExportFunction("f", "write", "int", ["int", "pointer", "int"]);
var lseek = getExportFunction("f", "lseek", "int64", ["int", "int64", "int"]);
var close = getExportFunction("f", "close", "int", ["int"]);
var remove = getExportFunction("f", "remove", "int", ["pointer"]);
var access = getExportFunction("f", "access", "int", ["pointer", "int"]);
var dlopen = getExportFunction("f", "dlopen", "pointer", ["pointer", "int"]);

function getCacheDir(index) {
	var NSUserDomainMask = 1;
	var npdirs = NSSearchPathForDirectoriesInDomains(index, NSUserDomainMask, 1);
	var len = ObjC.Object(npdirs).count();
	if (len == 0) {
		return '';
	}
	return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

function open(pathname, flags, mode) {
    if (typeof pathname == "string") {
        pathname = allocStr(pathname);
    }
    return wrapper_open(pathname, flags, mode);
}

// Export function
var modules = null;
function getAllAppModules() {
	if (modules == null) {
		modules = new Array();
		var tmpmods = Process.enumerateModulesSync();
		for (var i = 0; i < tmpmods.length; i++) {
			if (tmpmods[i].path.indexOf(".app") != -1) {
				modules.push(tmpmods[i]);
			}
		}
	}
	return modules;
}

var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function getDocumentDir() {
    var NSDocumentDirectory = 9;
    var NSUserDomainMask = 1;
    var npdirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, 1);
    return ObjC.Object(npdirs).objectAtIndex_(0).toString();
}

var FAT_MAGIC = 0xcafebabe;
var FAT_CIGAM = 0xbebafeca;
var MH_MAGIC = 0xfeedface;
var MH_CIGAM = 0xcefaedfe;
var MH_MAGIC_64 = 0xfeedfacf;
var MH_CIGAM_64 = 0xcffaedfe;
var LC_SEGMENT = 0x1;
var LC_SEGMENT_64 = 0x19;
var LC_ENCRYPTION_INFO = 0x21;
var LC_ENCRYPTION_INFO_64 = 0x2C;

function pad(str, n) {
    return Array(n-str.length+1).join("0")+str;
}

function swap32(value) {
    value = pad(value.toString(16),8)
    var result = "";
    for(var i = 0; i < value.length; i=i+2){
        result += value.charAt(value.length - i - 2);
        result += value.charAt(value.length - i - 1);
    }
    return parseInt(result,16)
}

function dumpMemory(base, size, path) {
    base = ptr(base);
    if(!access(allocStr(path),0)){
        remove(allocStr(path));
    }
    var fmodule = open(path, O_CREAT | O_WRONLY, 0);
    write(fmodule, base, size);
    close(fmodule);
    console.log(fmodule)
    console.log('dump to ' + path);
}

function dumpModule(name, path) {
    if (modules == null) {
        modules = getAllAppModules();
    }

    var targetmod = null;
    for (var i = 0; i < modules.length; i++) {
        if (modules[i].path.indexOf(name) != -1) {
            targetmod = modules[i];
            break;
        }
    }
    if (targetmod == null) {
        console.log("Cannot find module");
        return;
    }
    var modbase = modules[i].base;
    var modsize = modules[i].size;
    var newmodname = modules[i].name;
    if (!path) path = getDocumentDir();
    var newmodpath = path + "/" + newmodname + ".fid";
    var oldmodpath = modules[i].path;


    if(!access(allocStr(newmodpath),0)){
        remove(allocStr(newmodpath));
    }

    var fmodule = open(newmodpath, O_CREAT | O_RDWR, 0);
    var foldmodule = open(oldmodpath, O_RDONLY, 0);

    if (fmodule == -1 || foldmodule == -1) {
        console.log("Cannot open file" + newmodpath);
        return;
    }

    var is64bit = false;
    var size_of_mach_header = 0;
    var magic = getU32(modbase);
    var cur_cpu_type = getU32(modbase.add(4));
    var cur_cpu_subtype = getU32(modbase.add(8));
    if (magic == MH_MAGIC || magic == MH_CIGAM) {
        is64bit = false;
        size_of_mach_header = 28;
    }else if (magic == MH_MAGIC_64 || magic == MH_CIGAM_64) {
        is64bit = true;
        size_of_mach_header = 32;
    }

    var BUFSIZE = 4096;
    var buffer = malloc(BUFSIZE);

    read(foldmodule, buffer, BUFSIZE);

    var fileoffset = 0;
    var filesize = 0;
    magic = getU32(buffer);
    if(magic == FAT_CIGAM || magic == FAT_MAGIC){
        var off = 4;
        var archs = swap32(getU32(buffer.add(off)));
        for (var i = 0; i < archs; i++) {
            var cputype = swap32(getU32(buffer.add(off + 4)));
            var cpusubtype = swap32(getU32(buffer.add(off + 8)));
            if(cur_cpu_type == cputype && cur_cpu_subtype == cpusubtype){
                fileoffset = swap32(getU32(buffer.add(off + 12)));
                filesize = swap32(getU32(buffer.add(off + 16)));
                break;
            }
            off += 20;
        }

        if(fileoffset == 0 || filesize == 0)
            return;

        lseek(fmodule, 0, SEEK_SET);
        lseek(foldmodule, fileoffset, SEEK_SET);
        for(var i = 0; i < parseInt(filesize / BUFSIZE); i++) {
            read(foldmodule, buffer, BUFSIZE);
            write(fmodule, buffer, BUFSIZE);
        }
        if(filesize % BUFSIZE){
            read(foldmodule, buffer, filesize % BUFSIZE);
            write(fmodule, buffer, filesize % BUFSIZE);
        }
    }else{
        var readLen = 0;
        lseek(foldmodule, 0, SEEK_SET);
        lseek(fmodule, 0, SEEK_SET);
        while(readLen = read(foldmodule, buffer, BUFSIZE)) {
            write(fmodule, buffer, readLen);
        }
    }

    var ncmds = getU32(modbase.add(16));
    var off = size_of_mach_header;
    var offset_cryptid = -1;
    var crypt_off = 0;
    var crypt_size = 0;
    var segments = [];
    for (var i = 0; i < ncmds; i++) {
        var cmd = getU32(modbase.add(off));
        var cmdsize = getU32(modbase.add(off + 4));
        if (cmd == LC_ENCRYPTION_INFO || cmd == LC_ENCRYPTION_INFO_64) {
            offset_cryptid = off + 16;
            crypt_off = getU32(modbase.add(off + 8));
            crypt_size = getU32(modbase.add(off + 12));
        }
        off += cmdsize;
    }

    if (offset_cryptid != -1) {
        var tpbuf = malloc(8);
        putU64(tpbuf, 0);
        lseek(fmodule, offset_cryptid, SEEK_SET);
        write(fmodule, tpbuf, 4);
        lseek(fmodule, crypt_off, SEEK_SET);
        write(fmodule, modbase.add(crypt_off), crypt_size);
        console.log('modbase', modbase,'cryptoff',crypt_off,'crypt_size',crypt_size,'cryptid',offset_cryptid);
    }

    close(fmodule);
    close(foldmodule);
    return newmodpath
}

function dumpHeader(base) {
    var magic = base.readU32();
    var is64bit = false;
    if (magic == 0xfeedfacf) {
        is64bit = true;
    } else if (magic == 0xfeedface) {
        is64bit = false;
    } else {
        console.log('Unknown magic:' + magic);
    }
    var cmdnum = base.add(0x10).readU32();
    var cmdoff = is64bit?0x20:0x1C;
    for (var i = 0; i < cmdnum; i++) {
        var cmd = base.add(cmdoff).readU32();
        var cmdsize = base.add(cmdoff + 4).readU32();
        cmdoff += cmdsize;
        if (cmd == 1) { // SEGMENT
            var segname = base.add(cmdoff + 8).readUtf8String();
            var vmaddr = base.add(cmdoff + 0x18).readU32();
            var vmsize = base.add(cmdoff + 0x1C).readU32();
            var nsects = base.add(cmdoff + 0x40).readU8();
            var secbase = base.add(cmdoff + 0x38);
            if (base.add(cmdoff + 4).readU32() >= 0x38 + nsects*68)
            for (var i = 0; i < nsects; i++) {
                console.log('\t' + i + '/' + nsects + '-' + secbase.add(i*68).readUtf8String());
            }
            console.log(segname + ' ' + vmaddr.toString(16) + '-' + (vmaddr+vmsize).toString(16));
        } else if (cmd == 25) { // SEGMENT_64
            var segname = base.add(cmdoff + 8).readUtf8String();
            var vmaddr = base.add(cmdoff + 0x18).readU32();
            var vmsize = base.add(cmdoff + 0x20).readU32();
            var nsects = base.add(cmdoff + 0x40).readU8();
            var secbase = base.add(cmdoff + 0x48);
            if (base.add(cmdoff + 4).readU32() >= 0x48 + nsects*80)
            for (var i = 0; i < nsects; i++) {
                console.log('\t' + i + '/' + nsects + '-' + secbase.add(i*80).readUtf8String());
            }
            console.log(segname + ' ' + vmaddr.toString(16) + '-' + (vmaddr+vmsize).toString(16));
        }
    }
}
