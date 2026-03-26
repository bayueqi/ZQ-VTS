import { connect } from 'cloudflare:sockets';

function parseProxyAddress(proxyStr) {
    if (!proxyStr) return null;
    proxyStr = proxyStr.trim();
    if (proxyStr.startsWith('socks://') || proxyStr.startsWith('socks5://')) {
        const urlStr = proxyStr.replace(/^socks:\/\//, 'socks5://');
        try {
            const url = new URL(urlStr);
            if (!url.port) return null;
            return {
                type: 'socks5',
                host: url.hostname,
                port: parseInt(url.port),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (proxyStr.startsWith('http://') || proxyStr.startsWith('https://')) {
        try {
            const url = new URL(proxyStr);
            if (!url.port) return null;
            return {
                type: 'http',
                host: url.hostname,
                port: parseInt(url.port),
                username: url.username ? decodeURIComponent(url.username) : '',
                password: url.password ? decodeURIComponent(url.password) : ''
            };
        } catch (e) {
            return null;
        }
    }
    
    if (proxyStr.startsWith('[')) {
        const closeBracket = proxyStr.indexOf(']');
        if (closeBracket > 0) {
            const host = proxyStr.substring(1, closeBracket);
            const rest = proxyStr.substring(closeBracket + 1);
            if (rest.startsWith(':')) {
                const port = parseInt(rest.substring(1), 10);
                if (!isNaN(port) && port > 0 && port <= 65535) {
                    return { type: 'direct', host, port };
                }
            }
        }
    }
    
    const lastColonIndex = proxyStr.lastIndexOf(':');
    
    if (lastColonIndex > 0) {
        const host = proxyStr.substring(0, lastColonIndex);
        const portStr = proxyStr.substring(lastColonIndex + 1);
        const port = parseInt(portStr, 10);
        
        if (!isNaN(port) && port > 0 && port <= 65535) {
            return { type: 'direct', host, port };
        }
    }
    
    return null;
}

function rightRotate(value, amount) {
    return (value >>> amount) | (value << (32 - amount));
}

async function sha224(text) {
    const encoder = new TextEncoder();
    const data = encoder.encode(text);
    const K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2];
    let H = [0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4];
    const msgLen = data.length;
    const bitLen = msgLen * 8;
    const paddedLen = Math.ceil((msgLen + 9) / 64) * 64;
    const padded = new Uint8Array(paddedLen);
    padded.set(data);
    padded[msgLen] = 0x80;
    const view = new DataView(padded.buffer);
    view.setUint32(paddedLen - 4, bitLen, false);
    for (let chunk = 0; chunk < paddedLen; chunk += 64) {
        const W = new Uint32Array(64);
        for (let i = 0; i < 16; i++) {
            W[i] = view.getUint32(chunk + i * 4, false);
        }
        for (let i = 16; i < 64; i++) {
            const s0 = rightRotate(W[i - 15], 7) ^ rightRotate(W[i - 15], 18) ^ (W[i - 15] >>> 3);
            const s1 = rightRotate(W[i - 2], 17) ^ rightRotate(W[i - 2], 19) ^ (W[i - 2] >>> 10);
            W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
        }
        let [a, b, c, d, e, f, g, h] = H;
        for (let i = 0; i < 64; i++) {
            const S1 = rightRotate(e, 6) ^ rightRotate(e, 11) ^ rightRotate(e, 25);
            const ch = (e & f) ^ (~e & g);
            const temp1 = (h + S1 + ch + K[i] + W[i]) >>> 0;
            const S0 = rightRotate(a, 2) ^ rightRotate(a, 13) ^ rightRotate(a, 22);
            const maj = (a & b) ^ (a & c) ^ (b & c);
            const temp2 = (S0 + maj) >>> 0;
            h = g;
            g = f;
            f = e;
            e = (d + temp1) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (temp1 + temp2) >>> 0;
        }
        H[0] = (H[0] + a) >>> 0;
        H[1] = (H[1] + b) >>> 0;
        H[2] = (H[2] + c) >>> 0;
        H[3] = (H[3] + d) >>> 0;
        H[4] = (H[4] + e) >>> 0;
        H[5] = (H[5] + f) >>> 0;
        H[6] = (H[6] + g) >>> 0;
        H[7] = (H[7] + h) >>> 0;
    }
    const result = [];
    for (let i = 0; i < 7; i++) {
        result.push(
            ((H[i] >>> 24) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 16) & 0xff).toString(16).padStart(2, '0'),
            ((H[i] >>> 8) & 0xff).toString(16).padStart(2, '0'),
            (H[i] & 0xff).toString(16).padStart(2, '0')
        );
    }
    return result.join('');
}

async function parsetroHeader(buffer, passwordPlainText) {
    const sha224Password = await sha224(passwordPlainText);
    if (buffer.byteLength < 56) {
        return { hasError: true, message: "invalid data" };
    }
    let crLfIndex = 56;
    if (new Uint8Array(buffer.slice(56, 57))[0] !== 0x0d || new Uint8Array(buffer.slice(57, 58))[0] !== 0x0a) {
        return { hasError: true, message: "invalid header format" };
    }
    const password = new TextDecoder().decode(buffer.slice(0, crLfIndex));
    if (password !== sha224Password) {
        return { hasError: true, message: "invalid password" };
    }
    const socks5DataBuffer = buffer.slice(crLfIndex + 2);
    if (socks5DataBuffer.byteLength < 6) {
        return { hasError: true, message: "invalid S5 request data" };
    }
    const view = new DataView(socks5DataBuffer);
    const cmd = view.getUint8(0);
    if (cmd !== 1) {
        return { hasError: true, message: "unsupported command, only TCP is allowed" };
    }
    const atype = view.getUint8(1);
    let addressLength = 0;
    let addressIndex = 2;
    let address = "";
    switch (atype) {
        case 1: // IPv4
            addressLength = 4;
            address = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength)).join(".");
            break;
        case 3: // Domain
            addressLength = new Uint8Array(socks5DataBuffer.slice(addressIndex, addressIndex + 1))[0];
            addressIndex += 1;
            address = new TextDecoder().decode(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            break;
        case 4: // IPv6
            addressLength = 16;
            const dataView = new DataView(socks5DataBuffer.slice(addressIndex, addressIndex + addressLength));
            const ipv6 = [];
            for (let i = 0; i < 8; i++) {
                ipv6.push(dataView.getUint16(i * 2).toString(16));
            }
            address = ipv6.join(":");
            break;
        default:
            return { hasError: true, message: `invalid addressType is ${atype}` };
    }
    if (!address) {
        return { hasError: true, message: `address is empty, addressType is ${atype}` };
    }
    const portIndex = addressIndex + addressLength;
    const portBuffer = socks5DataBuffer.slice(portIndex, portIndex + 2);
    const portRemote = new DataView(portBuffer).getUint16(0);
    return {
        hasError: false,
        addressType: atype,
        port: portRemote,
        hostname: address,
        rawClientData: socks5DataBuffer.slice(portIndex + 4)
    };
}

function base64ToArray(b64Str) {
    if (!b64Str) return { error: null };
    try { 
        const binaryString = atob(b64Str.replace(/-/g, '+').replace(/_/g, '/'));
        const bytes = new Uint8Array(binaryString.length);
        for (let i = 0; i < binaryString.length; i++) {
            bytes[i] = binaryString.charCodeAt(i);
        }
        return { earlyData: bytes.buffer, error: null }; 
    } catch (error) { 
        return { error }; 
    }
}

function makeReadableStr(socket, earlyDataHeader) {
    let cancelled = false;
    return new ReadableStream({
        start(controller) {
            socket.addEventListener('message', (event) => { 
                if (!cancelled) controller.enqueue(event.data); 
            });
            socket.addEventListener('close', () => { 
                if (!cancelled) { 
                    controller.close(); 
                } 
            });
            socket.addEventListener('error', (err) => controller.error(err));
            const { earlyData, error } = base64ToArray(earlyDataHeader);
            if (error) controller.error(error); 
            else if (earlyData) controller.enqueue(earlyData);
        },
        cancel() { 
            cancelled = true; 
        }
    });
}

async function handleTroRequest(request, password, customProxyIP = null) {
    const wssPair = new WebSocketPair();
    const [clientSock, serverSock] = Object.values(wssPair);
    serverSock.accept();
    let remoteConnWrapper = { socket: null };
    const earlyData = request.headers.get('sec-websocket-protocol') || '';
    const readable = makeReadableStr(serverSock, earlyData);
    
    // 定义connect2Socks5函数
    const connect2Socks5 = async (proxyConfig, targetHost, targetPort, initialData) => {
        const { host, port } = proxyConfig;
        const socket = connect({ hostname: host, port: port });
        try {
            const { writer, reader } = await socks5Connect(socket, proxyConfig, targetHost, targetPort, 1000);
            await writer.write(initialData);
            writer.releaseLock();
            reader.releaseLock();
            return socket;
        } catch (error) {
            try { socket.close(); } catch (e) {}
            throw error;
        }
    };
    
    readable.pipeTo(new WritableStream({
        async write(chunk) {
            if (remoteConnWrapper.socket) {
                const writer = remoteConnWrapper.socket.writable.getWriter();
                await writer.write(chunk);
                writer.releaseLock();
                return;
            }
            const trojanResult = await parsetroHeader(chunk, password);
            if (!trojanResult.hasError) {
                const { port, hostname, rawClientData } = trojanResult;
                let remoteSock;
                if (customProxyIP) {
                    const proxyConfig = parseProxyAddress(customProxyIP);
                    if (proxyConfig && proxyConfig.type === 'socks5') {
                        // 使用SOCKS5代理
                        remoteSock = await connect2Socks5(proxyConfig, hostname, port, rawClientData);
                    } else {
                        // 使用普通代理IP
                        remoteSock = connect({ hostname: customProxyIP.split(':')[0], port: parseInt(customProxyIP.split(':')[1] || 443) });
                        const writer = remoteSock.writable.getWriter();
                        await writer.write(rawClientData);
                        writer.releaseLock();
                    }
                } else {
                    // 直连
                    remoteSock = connect({ hostname, port });
                    const writer = remoteSock.writable.getWriter();
                    await writer.write(rawClientData);
                    writer.releaseLock();
                }
                remoteConnWrapper.socket = remoteSock;
                remoteSock.readable.pipeTo(new WritableStream({
                    async write(chunk) {
                        if (serverSock.readyState === WebSocket.OPEN) {
                            serverSock.send(chunk);
                        }
                    },
                    abort() {}
                })).catch(() => {
                    try { serverSock.close(); } catch {}
                });
                return;
            }
            throw new Error('Invalid protocol');
        },
    })).catch((err) => {});
    return new Response(null, { status: 101, webSocket: clientSock });
}

async function socks5Handshake(socket, proxyConfig, timeoutMs) {
    const writer = socket.writable.getWriter();
    const reader = socket.readable.getReader();
    
    try {
        // SOCKS5 握手
        const authMethods = proxyConfig.username && proxyConfig.password ? 
            new Uint8Array([0x05, 0x02, 0x00, 0x02]) :
            new Uint8Array([0x05, 0x01, 0x00]);
        await writer.write(authMethods);
        const methodResponse = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({ timeout: true }), timeoutMs))]);
        if (!methodResponse || methodResponse.timeout || !methodResponse.value) {
            throw new Error('SOCKS5 握手超时');
        }
        
        // 认证
        const selectedMethod = new Uint8Array(methodResponse.value)[1];
        if (selectedMethod === 0x02) {
            if (!proxyConfig.username || !proxyConfig.password) {
                throw new Error('SOCKS5 需要认证');
            }
            const userBytes = new TextEncoder().encode(proxyConfig.username);
            const passBytes = new TextEncoder().encode(proxyConfig.password);
            const authPacket = new Uint8Array(3 + userBytes.length + passBytes.length);
            authPacket[0] = 0x01;
            authPacket[1] = userBytes.length;
            authPacket.set(userBytes, 2);
            authPacket[2 + userBytes.length] = passBytes.length;
            authPacket.set(passBytes, 3 + userBytes.length);
            await writer.write(authPacket);
            const authResponse = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({ timeout: true }), timeoutMs))]);
            if (!authResponse || authResponse.timeout) {
                throw new Error('SOCKS5 认证超时');
            } else if (new Uint8Array(authResponse.value)[1] !== 0x00) {
                throw new Error('SOCKS5 认证失败');
            }
        } else if (selectedMethod !== 0x00) {
            throw new Error(`SOCKS5 不支持的认证方法: ${selectedMethod}`);
        }
        
        return { writer, reader };
    } catch (error) {
        writer.releaseLock();
        reader.releaseLock();
        throw error;
    }
}

async function socks5Connect(socket, proxyConfig, targetHost, targetPort, timeoutMs) {
	const { writer, reader } = await socks5Handshake(socket, proxyConfig, timeoutMs);
	
	try {
		// 连接到目标主机
		const hostBytes = new TextEncoder().encode(targetHost);
		const connectPacket = new Uint8Array(7 + hostBytes.length);
		connectPacket[0] = 0x05;
		connectPacket[1] = 0x01;
		connectPacket[2] = 0x00;
		connectPacket[3] = 0x03;
		connectPacket[4] = hostBytes.length;
		connectPacket.set(hostBytes, 5);
		new DataView(connectPacket.buffer).setUint16(5 + hostBytes.length, targetPort, false);
		await writer.write(connectPacket);
		const connectResponse = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({ timeout: true }), timeoutMs))]);
		if (!connectResponse || connectResponse.timeout) {
			throw new Error('SOCKS5 连接超时');
		} else if (new Uint8Array(connectResponse.value)[1] !== 0x00) {
			throw new Error('SOCKS5 连接失败');
		}
		
		return { writer, reader };
	} catch (error) {
		writer.releaseLock();
		reader.releaseLock();
		throw error;
	}
}

function parseSSPacketHeader(chunk) {
	if (chunk.byteLength < 7) return { hasError: true, message: 'Invalid data' };
	try {
		const view = new Uint8Array(chunk);
		const addressType = view[0];
		let addrIdx = 1, addrLen = 0, addrValIdx = addrIdx, hostname = '';
		switch (addressType) {
			case 1: // IPv4
				addrLen = 4;
				hostname = new Uint8Array(chunk.slice(addrValIdx, addrValIdx + addrLen)).join('.');
				addrValIdx += addrLen;
				break;
			case 3: // Domain
				addrLen = view[addrIdx];
				addrValIdx += 1;
				hostname = new TextDecoder().decode(chunk.slice(addrValIdx, addrValIdx + addrLen));
				addrValIdx += addrLen;
				break;
			case 4: // IPv6
				addrLen = 16;
				const ipv6 = [];
				const ipv6View = new DataView(chunk.slice(addrValIdx, addrValIdx + addrLen));
				for (let i = 0; i < 8; i++) ipv6.push(ipv6View.getUint16(i * 2).toString(16));
				hostname = ipv6.join(':');
				addrValIdx += addrLen;
				break;
			default:
				return { hasError: true, message: `Invalid address type: ${addressType}` };
		}
		if (!hostname) return { hasError: true, message: `Invalid address: ${addressType}` };
		const port = new DataView(chunk.slice(addrValIdx, addrValIdx + 2)).getUint16(0);
		return { hasError: false, addressType, port, hostname, rawIndex: addrValIdx + 2 };
	} catch (e) {
		return { hasError: true, message: 'Failed to parse SS packet header' };
	}
}

async function handleSSRequest(request, password, customProxyIP = null) {
	const wssPair = new WebSocketPair();
	const [clientSock, serverSock] = Object.values(wssPair);
	serverSock.accept();
	let remoteConnWrapper = { socket: null };
	let isDnsQuery = false;
	const earlyData = request.headers.get('sec-websocket-protocol') || '';
	const readable = makeReadableStr(serverSock, earlyData);
	readable.pipeTo(new WritableStream({
		async write(chunk) {
			if (isDnsQuery) return await forwardataudp(chunk, serverSock, null);
			if (remoteConnWrapper.socket) {
				const writer = remoteConnWrapper.socket.writable.getWriter();
				await writer.write(chunk);
				writer.releaseLock();
				return;
			}
			const { hasError, message, addressType, port, hostname, rawIndex } = parseSSPacketHeader(chunk);
			if (hasError) throw new Error(message);

			// 检查是否是测速网站
			const speedTestDomains = ['speedtest.net','fast.com','speedtest.cn','speed.cloudflare.com', 'ovo.speedtestcustom.com'];
			if (speedTestDomains.includes(hostname)) {
				throw new Error('Speedtest site is blocked');
			}
			for (const domain of speedTestDomains) {
				if (hostname.endsWith('.' + domain)) {
					throw new Error('Speedtest site is blocked');
				}
			}

			if (addressType === 2) {
				if (port === 53) isDnsQuery = true;
				else throw new Error('UDP is not supported');
			}
			const rawData = chunk.slice(rawIndex);
			if (isDnsQuery) return forwardataudp(rawData, serverSock, null);
			await forwardataTCP(hostname, port, rawData, serverSock, null, remoteConnWrapper, customProxyIP);
		},
	})).catch((err) => {
		// console.error('Readable pipe error:', err);
	});
	return new Response(null, { status: 101, webSocket: clientSock });
}

async function forwardataTCP(host, portNum, rawData, ws, respHeader, remoteConnWrapper, customProxyIP) {
	async function connectDirect(address, port, data) {
		const remoteSock = connect({ hostname: address, port: port });
		const writer = remoteSock.writable.getWriter();
		await writer.write(data);
		writer.releaseLock();
		return remoteSock;
	}
	async function connect2Socks5(proxyConfig, targetHost, targetPort, initialData) {
		const { host, port } = proxyConfig;
		const socket = connect({ hostname: host, port: port });
		try {
			const { writer, reader } = await socks5Connect(socket, proxyConfig, targetHost, targetPort, 1000);
			await writer.write(initialData);
			writer.releaseLock();
			reader.releaseLock();
			return socket;
		} catch (error) {
			try { socket.close(); } catch (e) {}
			throw error;
		}
	}
	async function connectStreams(remoteSocket, webSocket, headerData, retryFunc) {
		let header = headerData, hasData = false;
		await remoteSocket.readable.pipeTo(
			new WritableStream({
				async write(chunk, controller) {
					hasData = true;
					if (webSocket.readyState !== WebSocket.OPEN) controller.error('wsreadyState not open');
					if (header) {
						const response = new Uint8Array(header.length + chunk.byteLength);
						response.set(header, 0);
						response.set(chunk, header.length);
						webSocket.send(response.buffer);
						header = null;
					} else {
						webSocket.send(chunk);
					}
				},
				abort() {},
			})
		).catch((err) => {
			try { webSocket.close(); } catch (e) {}
		});
		if (!hasData && retryFunc) {
			await retryFunc();
		}
	}
	let proxyConfig = null;
	let shouldUseProxy = false;
	let directProxyIP = null;
	if (customProxyIP) {
		proxyConfig = parseProxyAddress(customProxyIP);
		if (proxyConfig && (proxyConfig.type === 'socks5' || proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
			shouldUseProxy = true;
		} else {
			// 处理普通IP地址作为代理
			directProxyIP = customProxyIP;
			shouldUseProxy = true;
		}
	}
	async function connecttoPry() {
		let newSocket;
		if (proxyConfig && (proxyConfig.type === 'socks5')) {
			newSocket = await connect2Socks5(proxyConfig, host, portNum, rawData);
		} else if (directProxyIP) {
			// 使用普通IP地址作为代理
			const [ph, pp = portNum] = directProxyIP.split(':');
			newSocket = await connectDirect(ph, +pp || portNum, rawData);
		} else if (proxyConfig && (proxyConfig.type === 'http' || proxyConfig.type === 'https')) {
			// HTTP代理暂不支持
			newSocket = await connectDirect(host, portNum, rawData);
		} else {
			newSocket = await connectDirect(host, portNum, rawData);
		}
		remoteConnWrapper.socket = newSocket;
		newSocket.closed.catch(() => {}).finally(() => {
			try { ws.close(); } catch (e) {}
		});
		connectStreams(newSocket, ws, respHeader, null);
	}
	if (shouldUseProxy) {
		try {
			await connecttoPry();
		} catch (err) {
			throw err;
		}
	} else {
		try {
			const initialSocket = await connectDirect(host, portNum, rawData);
			remoteConnWrapper.socket = initialSocket;
			connectStreams(initialSocket, ws, respHeader, connecttoPry);
		} catch (err) {
			await connecttoPry();
		}
	}
}

async function forwardataudp(udpChunk, webSocket, respHeader) {
	try {
		const tcpSocket = connect({ hostname: '8.8.4.4', port: 53 });
		let vlessHeader = respHeader;
		const writer = tcpSocket.writable.getWriter();
		await writer.write(udpChunk);
		writer.releaseLock();
		await tcpSocket.readable.pipeTo(new WritableStream({
			async write(chunk) {
				if (webSocket.readyState === WebSocket.OPEN) {
					if (vlessHeader) {
						const response = new Uint8Array(vlessHeader.length + chunk.byteLength);
						response.set(vlessHeader, 0);
						response.set(chunk, vlessHeader.length);
						webSocket.send(response.buffer);
						vlessHeader = null;
					} else {
						webSocket.send(chunk);
					}
				}
			},
		}));
	} catch (error) {
		// console.error('UDP forward error:', error);
	}
}

export default {
	async fetch(req, env) {
		const getUserConfig = async () => {
		try {
			const config = await env.VTS?.get('user_config', 'json');
			const merged = config || { uuid: 'ef9d104e-ca0e-4202-ba4b-a0afb969c747', domain: '', port: '443', s5: '', proxyIp: '', password: '', domains: [], ports: [] };
			merged.domains = Array.isArray(merged.domains) ? merged.domains : [];
			merged.ports = Array.isArray(merged.ports) ? merged.ports : [];
			const d = (merged.domain || '').trim();
			if (d && !merged.domains.includes(d)) merged.domains.push(d);
			const pNum = Math.max(1, Math.min(65535, parseInt(merged.port || '443', 10) || 443));
			if (!merged.ports.some(x => +x === pNum)) merged.ports.push(pNum);
			return merged;
		} catch {
			return { uuid: 'ef9d104e-ca0e-4202-ba4b-a0afb969c747', domain: '', port: '443', s5: '', proxyIp: '', password: '', domains: [], ports: [443] };
		}
	};

		const buildVlessUri = (rawPathQuery, uuid, label, workerHost, preferredDomain, port, s5, proxyIp) => {
				let path = rawPathQuery;
				if (!path) {
					if (s5 && !proxyIp) {
						// 仅SOCKS5时使用mode=s5确保严格SOCKS5连接
						const params = ['mode=s5'];
						params.push('s5=' + encodeURIComponent(s5));
						path = '/?' + params.join('&');
					} else if (proxyIp && !s5) {
						// 仅ProxyIP时使用mode=proxy确保严格ProxyIP连接
						const params = ['mode=proxy'];
						params.push('proxyip=' + encodeURIComponent(proxyIp));
						path = '/?' + params.join('&');
					} else {
						// 其他情况使用原始逻辑
						const params = ['mode=auto', 'direct'];
						if (s5) params.push('s5=' + encodeURIComponent(s5));
						if (proxyIp) params.push('proxyip=' + encodeURIComponent(proxyIp));
						path = s5 || proxyIp ? '/?' + params.join('&') : '/?mode=direct';
					}
				}
				return `vless://${uuid}@${preferredDomain}:${port}?encryption=none&security=tls&sni=${workerHost}&type=ws&host=${workerHost}&path=${encodeURIComponent(path)}#${encodeURIComponent(label || preferredDomain)}`;
			};

		const buildTrojanUri = (password, label, workerHost, preferredDomain, port, proxyIp) => {
			let path = '/?mode=trojan';
			if (proxyIp) path += '&proxyip=' + encodeURIComponent(proxyIp);
			path += '&ed=2560';
			return `trojan://${password}@${preferredDomain}:${port}?security=tls&sni=${workerHost}&fp=firefox&allowInsecure=0&type=ws&host=${workerHost}&path=${encodeURIComponent(path)}#${encodeURIComponent(label || preferredDomain)}`;
		};

		const buildShadowsocksUri = (password, label, workerHost, preferredDomain, port, proxyIp) => {
			const validPath = `/${password}`;
			let path = `${validPath}/?ed=2560`;
			if (proxyIp) path += '&proxyip=' + encodeURIComponent(proxyIp);
			const ssConfig = `none:${password}`;
			const encodedConfig = btoa(ssConfig);
			return `ss://${encodedConfig}@${preferredDomain}:${port}?plugin=v2ray-plugin;mode%3Dwebsocket;host%3D${workerHost};path%3D${encodeURIComponent(path)};tls;sni%3D${workerHost};skip-cert-verify%3Dtrue;mux%3D0#${encodeURIComponent(label || preferredDomain)}`;
		};

		const buildVariants = (s5, proxyIp) => {
		const v = [{ label: '仅直连', raw: '/?mode=direct' }];
		if (s5) {
			const s5Enc = encodeURIComponent(s5);
			v.push({ label: '仅SOCKS5', raw: `/?mode=s5&s5=${s5Enc}` });
			v.push({ label: '直连+SOCKS5', raw: `/?mode=parallel&direct&s5=${s5Enc}` });
		}
		if (proxyIp) {
			const proxyIpEnc = encodeURIComponent(proxyIp);
			v.push({ label: '仅ProxyIP', raw: `/?mode=proxy&proxyip=${proxyIpEnc}` });
			v.push({ label: '直连+ProxyIP', raw: `/?mode=parallel&direct&proxyip=${proxyIpEnc}` });
		}
		if (s5 && proxyIp) {
			const s5Enc = encodeURIComponent(s5);
			const proxyIpEnc = encodeURIComponent(proxyIp);
			v.push({ label: '直连+SOCKS5+ProxyIP', raw: `/?mode=parallel&direct&s5=${s5Enc}&proxyip=${proxyIpEnc}` });
		}
		return v;
	};

		const getDomainPortLists = (request, cfg) => {
			const workerHost = new URL(request.url).hostname;
			const domains = [...new Set((cfg.domains || []).map(x => (x || '').trim()).filter(Boolean))];
			if (!domains.length) domains.push((cfg.domain || workerHost).trim() || workerHost);
			const ports = [...new Set((cfg.ports || []).concat(cfg.port || []).map(p => Math.max(1, Math.min(65535, +p || 443))))];
			if (!ports.length) ports.push(443);
			return { workerHost, domains, ports };
		};

		const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { 'content-type': 'application/json; charset=utf-8' } });

		if (req.headers.get('Upgrade')?.toLowerCase() === 'websocket') {
			const u = new URL(req.url);
			const userConfig = await getUserConfig();
			const pathname = u.pathname;
			
			// 处理Shadowsocks连接
			if (userConfig.password && pathname.toLowerCase().startsWith(`/${userConfig.password.toLowerCase()}`)) {
				const customProxyIP = u.searchParams.get('proxyip');
				return await handleSSRequest(req, userConfig.password, customProxyIP);
			}
			
			if (u.searchParams.get('mode') === 'trojan' && userConfig.password) {
				const customProxyIP = u.searchParams.get('proxyip');
				return await handleTroRequest(req, userConfig.password, customProxyIP);
			}
			
			const [client, ws] = Object.values(new WebSocketPair());
			ws.accept();

			if (u.pathname.includes('%3F')) {
				const decoded = decodeURIComponent(u.pathname);
				const queryIndex = decoded.indexOf('?');
				if (queryIndex !== -1) {
					u.search = decoded.substring(queryIndex);
					u.pathname = decoded.substring(0, queryIndex);
				}
			}

			const mode = u.searchParams.get('mode') || 'auto';
			const s5Param = u.searchParams.get('s5');
			const proxyParam = u.searchParams.get('proxyip');
			
			let proxyConfig = null;
			if (s5Param) {
					proxyConfig = parseProxyAddress(s5Param);
					if (!proxyConfig || proxyConfig.type !== 'socks5') {
						const path = s5Param;
						if (path.includes('@')) {
							const [cred, server] = path.split('@');
							const [user, pass] = cred.split(':');
							const [host, port] = server.split(':');
							if (host && port) {
								proxyConfig = { type: 'socks5', host, port: +port, username: user, password: pass };
							}
						} else if (path.includes(':')) {
							const [host, port] = path.split(':');
							if (host && port) {
								proxyConfig = { type: 'socks5', host, port: +port, username: '', password: '' };
							}
						}
					}
				}
			
			const PROXY_IP = proxyParam ? String(proxyParam) : null;

			const getOrder = () => {
					if (mode === 'proxy') return ['proxy'];
					if (mode === 's5') return ['s5'];
					const order = u.search.slice(1).split('&').map(pair => {
						const key = pair.split('=')[0];
						if (key === 'direct') return 'direct';
						if (key === 's5') return 's5';
						if (key === 'proxyip') return 'proxy';
						return null;
					}).filter(Boolean);
					// 当只有s5参数时，返回['s5']确保严格使用SOCKS5
					if (order.length === 1 && order[0] === 's5') return ['s5'];
					return order.length ? order : ['direct'];
				};

			let remote = null, udpWriter = null, isDNS = false;
			
			const connect2Socks5 = async (proxyConfig, targetHost, targetPort, initialData) => {
				const { host, port } = proxyConfig;
				const socket = connect({ hostname: host, port: port });
				try {
					const { writer, reader } = await socks5Connect(socket, proxyConfig, targetHost, targetPort, 1000);
					await writer.write(initialData);
					writer.releaseLock();
					reader.releaseLock();
					return socket;
				} catch (error) {
					try { socket.close(); } catch (e) {}
					throw error;
				}
			};

			new ReadableStream({
				start(ctrl) {
					ws.addEventListener('message', e => ctrl.enqueue(e.data));
					ws.addEventListener('close', () => {
						remote?.close();
						ctrl.close();
					});
					ws.addEventListener('error', () => {
						remote?.close();
						ctrl.error();
					});

					const early = req.headers.get('sec-websocket-protocol');
					if (early) {
						try {
							ctrl.enqueue(Uint8Array.from(atob(early.replace(/-/g, '+').replace(/_/g, '/')),
								c => c.charCodeAt(0)).buffer);
						} catch {}
					}
				}
			}).pipeTo(new WritableStream({
				async write(data) {
					if (isDNS) return udpWriter?.write(data);
					if (remote) {
						const w = remote.writable.getWriter();
						await w.write(data);
						w.releaseLock();
						return;
					}

					if (data.byteLength < 24) return;
					const uuidBytes = new Uint8Array(data.slice(1, 17));
					const expectedUUID = userConfig.uuid.replace(/-/g, '');
					for (let i = 0; i < 16; i++) {
						if (uuidBytes[i] !== parseInt(expectedUUID.substr(i * 2, 2), 16)) return;
					}

					const view = new DataView(data);
					const optLen = view.getUint8(17);
					const cmd = view.getUint8(18 + optLen);
					if (cmd !== 1 && cmd !== 2) return;

					let pos = 19 + optLen;
					const port = view.getUint16(pos);
					const type = view.getUint8(pos + 2);
					pos += 3;

					let addr = '';
					if (type === 1) {
						addr =
							`${view.getUint8(pos)}.${view.getUint8(pos + 1)}.${view.getUint8(pos + 2)}.${view.getUint8(pos + 3)}`;
						pos += 4;
					} else if (type === 2) {
						const len = view.getUint8(pos++);
						addr = new TextDecoder().decode(data.slice(pos, pos + len));
						pos += len;
					} else if (type === 3) {
						const ipv6 = [];
						for (let i = 0; i < 8; i++, pos += 2) ipv6.push(view.getUint16(pos)
							.toString(16));
						addr = ipv6.join(':');
					} else return;

					const header = new Uint8Array([data[0], 0]);
					const payload = data.slice(pos);
					if (cmd === 2) {
						if (port !== 53) return;
						isDNS = true;
						let sent = false;
						const {
							readable,
							writable
						} = new TransformStream({
							transform(chunk, ctrl) {
								for (let i = 0; i < chunk.byteLength;) {
									const len = new DataView(chunk.slice(i, i + 2))
										.getUint16(0);
									ctrl.enqueue(chunk.slice(i + 2, i + 2 + len));
									i += 2 + len;
								}
							}
						});

						readable.pipeTo(new WritableStream({
							async write(query) {
								try {
									const resp = await fetch(
										'https://1.1.1.1/dns-query', {
											method: 'POST',
											headers: {
												'content-type': 'application/dns-message'
											},
											body: query
										});
									if (ws.readyState === 1) {
										const result = new Uint8Array(await resp
											.arrayBuffer());
										ws.send(new Uint8Array([...(sent ? [] :
												header), result
											.length >> 8, result
											.length & 0xff, ...result
										]));
										sent = true;
									}
								} catch {}
							}
						}));
						udpWriter = writable.getWriter();
						return udpWriter.write(payload);
					}
					const connectDirect = async (hostname, portNum, data) => {
						const sock = connect({ hostname: hostname, port: portNum });
						await sock.opened;
						const writer = sock.writable.getWriter();
						await writer.write(data);
						writer.releaseLock();
						return sock;
					};
					const connectStreams = async (remoteSocket, webSocket, headerData, retryFunc) => {
					let header = headerData, hasData = false, dataPromiseResolve;
					const dataPromise = new Promise(resolve => dataPromiseResolve = resolve);
					const timeoutId = setTimeout(() => {
						if (!hasData) dataPromiseResolve(false);
					}, 100);
					remoteSocket.readable.pipeTo(
						new WritableStream({
							async write(chunk, controller) {
								clearTimeout(timeoutId);
								hasData = true;
								dataPromiseResolve(true);
								if (webSocket.readyState !== 1) controller.error('ws.readyState is not open');
								if (header) {
									const response = new Uint8Array(header.length + chunk.byteLength);
									response.set(header, 0);
									response.set(chunk, header.length);
									webSocket.send(response.buffer);
									header = null;
								} else {
									webSocket.send(chunk);
								}
							},
							abort() {}
						})
					).catch(() => {
						try { webSocket.readyState === 1 && webSocket.close(); } catch {}
					});
					const receivedData = await dataPromise;
					if (!receivedData && retryFunc) await retryFunc();
				};
					const connectParallel = async () => {
					let domainProxyMapping = {};
					try {
						const mappingStr = await env.VTS?.get('domain_proxy_mapping', 'json');
						if (mappingStr) domainProxyMapping = mappingStr;
					} catch {}
					const tryConnect = async (type) => {
						try {
							if (type === 'direct') return await connectDirect(addr, port, payload);
							if (type === 's5' && proxyConfig) {
								return await connect2Socks5(proxyConfig, addr, port, payload);
							}
							if (type === 'proxy') {
								let proxyIp = PROXY_IP;
								if (addr && domainProxyMapping[addr]) proxyIp = domainProxyMapping[addr];
								if (proxyIp) {
									const [ph, pp = port] = proxyIp.split(':');
									return await connectDirect(ph, +pp || port, payload);
								}
							}
						} catch {}
						return null;
					};
					const order = getOrder();
					if (!order.length) return;
					const tryNext = async (index) => {
						if (index >= order.length) return null;
						const sock = await tryConnect(order[index]);
						return sock || await tryNext(index + 1);
					};
					
					// 仅 SOCKS5 模式：只尝试 SOCKS5 连接
						if (mode === 's5') {
							const sock = await tryConnect('s5');
							if (sock) {
								remote = sock;
								await connectStreams(sock, ws, header, null);
							}
							return;
						}
						// 仅 Proxy 模式：只尝试 Proxy 连接
						if (mode === 'proxy') {
							const sock = await tryConnect('proxy');
							if (sock) {
								remote = sock;
								await connectStreams(sock, ws, header, null);
							}
							return;
						}
					
					const primary = await tryConnect(order[0]);
					if (!primary) {
						const backup = await tryNext(1);
						if (backup) {
							remote = backup;
							await connectStreams(backup, ws, header, null);
						}
						return;
					}
					remote = primary;
					const retryFunc = order.length > 1 ? async () => {
						const backup = await tryNext(1);
						if (backup) {
							try { primary.close(); } catch {}
							remote = backup;
							await connectStreams(backup, ws, header, null);
						}
					} : null;
					await connectStreams(primary, ws, header, retryFunc);
				};
					await connectParallel();
				}
			})).catch(() => {});

			return new Response(null, {
				status: 101,
				webSocket: client
			});
		}

		const url = new URL(req.url);


		if (url.pathname.startsWith('/api/config/')) {
			const pathParts = url.pathname.split('/').filter(p => p);
			const urlUUID = pathParts[2];
			if (!urlUUID) {
				return json({ error: 'UUID不能为空' }, 400);
			}
			const userConfig = await getUserConfig();
			if (req.method === 'GET') {
				if (urlUUID !== userConfig.uuid) {
					return json({ error: 'UUID错误，无权访问' }, 403);
				}
				const { fallbackTimeout, ...configWithoutTimeout } = userConfig;
				return json(configWithoutTimeout);
			} else if (req.method === 'POST') {
				try {
					const incoming = await req.json();
					if (!incoming.uuid || typeof incoming.uuid !== 'string') {
						return json({ error: 'UUID不能为空' }, 400);
					}
					if (urlUUID !== userConfig.uuid && urlUUID !== incoming.uuid) {
						return json({ error: 'UUID错误，无权访问' }, 403);
					}
					let domains = Array.isArray(incoming.domains) ? incoming.domains.map(x => (x || '').trim()).filter(Boolean) : [];
					if (incoming.domain) {
						const d = (incoming.domain + '').trim();
						if (d && !domains.includes(d)) domains.unshift(d);
					}
					let ports = Array.isArray(incoming.ports) ? incoming.ports.map(x => Math.max(1, Math.min(65535, parseInt((x + ''), 10) || 443))) : [];
					if (incoming.port) {
						const pn = Math.max(1, Math.min(65535, parseInt((incoming.port + ''), 10) || 443));
						if (!ports.includes(pn)) ports.unshift(pn);
					}
					domains = [...new Set(domains)];
					ports = [...new Set(ports)];
					if (!domains.length) domains.push('');
					if (!ports.length) ports.push(443);
					const normalized = { uuid: incoming.uuid, domain: (domains[0] || ''), port: String(ports[0] || 443), s5: incoming.s5 || '', proxyIp: incoming.proxyIp || '', password: incoming.password || '', domains: domains.filter(Boolean), ports };
					if (env.VTS) {
					await env.VTS.put('user_config', JSON.stringify(normalized));
					if (normalized.domain && normalized.proxyIp) {
						const domainProxyMapping = { [normalized.domain]: normalized.proxyIp };
						await env.VTS.put('domain_proxy_mapping', JSON.stringify(domainProxyMapping));
					}
				}
					return json({ success: true, message: '配置保存成功' });
				} catch (error) {
					return json({ error: '配置保存失败' }, 500);
				}
			}
		}

		if (url.pathname === '/api/probe') {
			const params = url.searchParams, inputUUID = params.get('uuid');
			if (!inputUUID) return json({ ok: false, message: '缺少 UUID 参数' }, 400);
			const userConfig = await getUserConfig();
			if (inputUUID !== userConfig.uuid) return json({ ok: false, message: 'UUID 错误，无权访问' }, 403);
			const type = params.get('type'), timeoutMs = Math.max(50, Math.min(20000, +(params.get('timeout') || 0) || 1000)), started = Date.now();
			try {
				if (type === 'proxyip') {
					const [host, port = 443] = (params.get('proxyip') || userConfig.proxyIp || '').split(':');
					if (!host) return json({ ok: false, ms: 0, message: '未填写 ProxyIP' }, 400);
					const sock = connect({ hostname: host, port: +port });
					const res = await Promise.race([sock.opened.then(() => 'ok'), new Promise(r => setTimeout(() => r('timeout'), timeoutMs))]);
					try { sock.close(); } catch {}
					return json({ ok: res === 'ok', ms: Date.now() - started, message: res === 'ok' ? '可用' : '连接超时' }, res === 'ok' ? 200 : 408);
				}
				if (type === 's5') {
				const raw = params.get('s5') || userConfig.s5 || '';
				if (!raw) return json({ ok: false, ms: 0, message: '未填写 SOCKS5' }, 400);
				
				// 解析 SOCKS5 代理地址
				let proxyConfig = parseProxyAddress(raw);
				if (!proxyConfig || proxyConfig.type !== 'socks5') {
					const path = raw;
					if (path.includes('@')) {
						const [cred, server] = path.split('@');
						const [user, pass] = cred.split(':');
						const [host, port] = server.split(':');
						if (host && port) {
							proxyConfig = { type: 'socks5', host, port: +port, username: user, password: pass };
						}
					} else if (path.includes(':')) {
						const [host, port] = path.split(':');
						if (host && port) {
							proxyConfig = { type: 'socks5', host, port: +port, username: '', password: '' };
						}
					}
				}
				
				if (!proxyConfig || proxyConfig.type !== 'socks5') {
					return json({ ok: false, ms: 0, message: 'SOCKS5 地址格式错误' }, 400);
				}
				
				// 使用 SOCKS5 代理访问 https://ipinfo.io
				try {
					// 建立 SOCKS5 连接
					const sock = connect({ hostname: proxyConfig.host, port: proxyConfig.port });
					const { writer, reader } = await socks5Connect(sock, proxyConfig, 'ipinfo.io', 443, timeoutMs);
					
					// 发送 HTTPS 请求
					const httpsRequest = `GET / HTTP/1.1\r\n` +
						`Host: ipinfo.io\r\n` +
						`User-Agent: Mozilla/5.0\r\n` +
						`Connection: close\r\n` +
						`\r\n`;
					await writer.write(new TextEncoder().encode(httpsRequest));
					
					// 读取响应
				const response = await Promise.race([reader.read(), new Promise(r => setTimeout(() => r({ timeout: true }), timeoutMs))]);
				if (!response || response.timeout || !response.value) {
					return json({ ok: false, ms: Date.now() - started, message: 'HTTP 请求超时' }, 408);
				}
				
				// 清理
				writer.releaseLock();
				reader.releaseLock();
				sock.close();
				
				return json({ ok: true, ms: Date.now() - started, message: '可用' }, 200);
			} catch (error) {
					const status = error.message.includes('超时') ? 408 : error.message.includes('认证') ? 401 : 400;
					return json({ ok: false, ms: Date.now() - started, message: error.message || '探测失败' }, status);
				}
			}
				return json({ ok: false, ms: 0, message: 'type 参数无效' }, 400);
			} catch (e) {
				return json({ ok: false, ms: Date.now() - started, message: '探测失败' }, 500);
			}
		}

		if (url.pathname.startsWith('/sub')) {
			const parts = url.pathname.split('/').filter(p => p);
			const inputUUID = url.searchParams.get('uuid') || parts[1];
			if (!inputUUID) return new Response('missing uuid', { status: 400 });
			const userConfig = await getUserConfig();
			if (inputUUID !== userConfig.uuid) return new Response('Not Found', { status: 404 });
			const { workerHost, domains, ports } = getDomainPortLists(req, userConfig);
			const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
			const ua = (req.headers.get('User-Agent') || '').toLowerCase();
			const isSubConverterRequest = url.searchParams.has('b64') || url.searchParams.has('base64') || req.headers.get('subconverter-request') || req.headers.get('subconverter-version') || ua.includes('subconverter');
			const 订阅类型 = isSubConverterRequest ? 'mixed' : 
					url.searchParams.has('target') ? url.searchParams.get('target') :
					url.searchParams.has('clash') || ua.includes('clash') || ua.includes('meta') || ua.includes('mihomo') ? 'clash' :
					url.searchParams.has('sb') || url.searchParams.has('singbox') || ua.includes('singbox') || ua.includes('sing-box') ? 'singbox' :
					url.searchParams.has('surge') || ua.includes('surge') ? 'surge&ver=4' :
					url.searchParams.has('quanx') || ua.includes('quantumult') ? 'quanx' :
					url.searchParams.has('loon') || ua.includes('loon') ? 'loon' : 'mixed';
			const out = [];
			for (const d of domains) {
				for (const p of ports) {
					for (const v of variants) out.push(buildVlessUri(v.raw, userConfig.uuid, `${v.label} ${d}:${p}`, workerHost, d, p, userConfig.s5, userConfig.proxyIp));
					if (userConfig.password) out.push(buildTrojanUri(userConfig.password, `[Trojan] 仅直连 ${d}:${p}`, workerHost, d, p, null));
					if (userConfig.password && userConfig.proxyIp) out.push(buildTrojanUri(userConfig.password, `[Trojan] 仅ProxyIP ${d}:${p}`, workerHost, d, p, userConfig.proxyIp));
					if (userConfig.password) out.push(buildShadowsocksUri(userConfig.password, `[SS] 仅直连 ${d}:${p}`, workerHost, d, p, null));
					if (userConfig.password && userConfig.proxyIp) out.push(buildShadowsocksUri(userConfig.password, `[SS] 仅ProxyIP ${d}:${p}`, workerHost, d, p, userConfig.proxyIp));
				}
			}
			const nodesContent = out.join('\n');
			const responseHeaders = {
				"content-type": "text/plain; charset=utf-8",
				"Profile-Update-Interval": "3",
				"Profile-web-page-url": new URL(req.url).origin + '/' + userConfig.uuid,
				"Cache-Control": "no-store",
				"Content-Disposition": "attachment; filename=vts"
			};
			
			if (订阅类型 === 'mixed') {
					const encoded = btoa(unescape(encodeURIComponent(nodesContent)));
					return new Response(encoded + '\n', { status: 200, headers: responseHeaders });
				} else {
					const encodedNodes = btoa(unescape(encodeURIComponent(nodesContent)));
					const 订阅转换URL = `https://subapi.vpnjacky.dpdns.org/sub?target=${订阅类型}&url=${encodeURIComponent(encodedNodes)}&emoji=false&insert=false`;
					try {
						const response = await fetch(订阅转换URL, { 
							headers: { 
								'User-Agent': 'Subconverter for ' + 订阅类型,
								'Accept': '*/*'
							}
						});
						if (response.ok) {
							const 转换后内容 = await response.text();
							if (订阅类型 === 'clash') responseHeaders["content-type"] = 'application/x-yaml; charset=utf-8';
							else if (订阅类型 === 'singbox') responseHeaders["content-type"] = 'application/json; charset=utf-8';
							return new Response(转换后内容, { status: 200, headers: responseHeaders });
						} else {
							const errorText = await response.text().catch(() => '');
							return text('订阅转换失败: ' + response.statusText + '\n' + errorText + '\nURL: ' + 订阅转换URL, 500);
						}
					} catch {
						return new Response(encodedNodes + '\n', { status: 200, headers: responseHeaders });
					}
				}
		}

		if (url.pathname === '/' || url.pathname === '/index.html') {
			const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZQ-VTS</title><link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/03/26/928324.svg"><style>:root{--primary:#2563eb;--primary-light:#3b82f6;--primary-dark:#1d4ed8;--bg-gradient-start:#eff6ff;--bg-gradient-end:#dbeafe;--card-bg:rgba(255,255,255,0.95);--text-primary:#1e3a5f;--text-secondary:#64748b;--border-color:#bfdbfe;--shadow:0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);--shadow-lg:0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;margin:0;min-height:100vh;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);color:var(--text-primary);line-height:1.6;display:flex;align-items:center;justify-content:center}.card{background:var(--card-bg);border-radius:20px;padding:32px;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);max-width:500px;width:90%;backdrop-filter:blur(10px)}h1{margin:0 0 24px;font-size:28px;font-weight:700;text-align:center;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.form-group{margin-bottom:20px}label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-primary)}input[type="text"]{width:100%;padding:14px;border:2px solid var(--border-color);border-radius:12px;background:rgba(255,255,255,0.8);color:var(--text-primary);font-size:16px;box-sizing:border-box;transition:all .3s ease}input[type="text"]:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,0.1)}button{width:100%;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;border:none;border-radius:12px;padding:14px;font-size:16px;font-weight:600;cursor:pointer;transition:all .3s ease;box-shadow:var(--shadow)}button:hover{background:linear-gradient(135deg,var(--primary-dark) 0%,var(--primary) 100%);transform:translateY(-2px);box-shadow:var(--shadow-lg)}.error{margin-top:16px;color:#dc2626;text-align:center;font-size:14px;padding:12px;border-radius:8px;background:rgba(220,38,38,0.1);border:1px solid rgba(220,38,38,0.2)}</style></head><body><div class="card"><h1>ZQ-VTS</h1><form method="get"><div class="form-group"><label for="uuid">请输入UUID</label><input type="text" id="uuid" name="uuid" required placeholder="请输入正确的UUID"></div><button type="submit">进入节点界面</button></form><div class="error" id="error" style="display:none">UUID错误，请检查后重新输入</div></div><script>document.querySelector('form').addEventListener('submit',function(e){e.preventDefault();const uuid=document.getElementById('uuid').value.trim();if(!uuid)return;fetch('/' + uuid).then(response=>{if(response.ok){window.location.href='/' + uuid;}else{const errorDiv=document.getElementById('error');errorDiv.style.display='block';errorDiv.textContent='UUID错误，请检查后重新输入';}}).catch(()=>{const errorDiv=document.getElementById('error');errorDiv.style.display='block';errorDiv.textContent='UUID错误，请检查后重新输入';});});</script></body></html>`;
			return new Response(html, {headers:{'content-type':'text/html; charset=utf-8'}});
		}

		// Node interface at /{UUID}
		const pathParts = url.pathname.split('/').filter(p => p);
		if (pathParts.length === 1) {
			const inputUUID = pathParts[0];
			
			// Get user config
			const userConfig = await getUserConfig();
			
			// Check if input UUID matches user config UUID
			if (inputUUID !== userConfig.uuid) {
				return new Response('Not Found', { status: 404 });
			}
			const userUUID = userConfig.uuid;
			const origin = new URL(req.url).origin;
			const subUrl = `${origin}/sub/${userUUID}`;
			
			const lists = getDomainPortLists(req, userConfig);
			const variants = buildVariants(userConfig.s5, userConfig.proxyIp);
			const allNodeUris = [];
			for (const d of lists.domains) {
				for (const p of lists.ports) {
					for (const v of variants) {
						const full = buildVlessUri(v.raw, userUUID, `${v.label} ${d}:${p}`, lists.workerHost, d, p, userConfig.s5, userConfig.proxyIp);
						allNodeUris.push(full);
					}
				}
			}
			const allNodesJson = JSON.stringify(allNodeUris);
			const html = `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>ZQ-VTS</title><link rel="icon" type="image/png" href="https://img.520jacky.dpdns.org/i/2026/03/26/928324.svg"><style>:root{--primary:#2563eb;--primary-light:#3b82f6;--primary-dark:#1d4ed8;--bg-gradient-start:#eff6ff;--bg-gradient-end:#dbeafe;--card-bg:rgba(255,255,255,0.95);--text-primary:#1e3a5f;--text-secondary:#64748b;--border-color:#bfdbfe;--shadow:0 4px 6px -1px rgba(37,99,235,0.1),0 2px 4px -1px rgba(37,99,235,0.06);--shadow-lg:0 20px 25px -5px rgba(37,99,235,0.15),0 10px 10px -5px rgba(37,99,235,0.1)}*{box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,'Helvetica Neue',Arial,sans-serif;margin:0;min-height:100vh;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);color:var(--text-primary);line-height:1.6}.wrap{max-width:1000px;margin:0 auto;padding:32px 24px;position:relative}.header{text-align:center;margin-bottom:32px;padding:24px 0;border-bottom:2px solid var(--border-color)}h1{margin:0;font-size:32px;font-weight:700;background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text}.subtitle{color:var(--text-secondary);margin-top:8px;font-size:14px}.topbar{position:absolute;right:24px;top:32px;display:flex;gap:12px}.topbar a{width:42px;height:42px;border-radius:12px;background:var(--card-bg);border:1px solid var(--border-color);color:var(--primary);display:inline-flex;align-items:center;justify-content:center;transition:all .3s ease;box-shadow:var(--shadow)}.topbar a:hover{background:var(--primary);color:#fff;transform:translateY(-2px);box-shadow:var(--shadow-lg)}.main-card{background:var(--card-bg);border-radius:20px;padding:28px;margin-bottom:24px;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);backdrop-filter:blur(10px)}.section-title{font-size:18px;font-weight:600;color:var(--primary);margin-bottom:16px;display:flex;align-items:center;gap:8px}.section-title::before{content:'';width:4px;height:20px;background:linear-gradient(180deg,var(--primary) 0%,var(--primary-light) 100%);border-radius:2px}.url-box{background:linear-gradient(135deg,#f8fafc 0%,#f1f5f9 100%);border:2px solid var(--border-color);border-radius:12px;padding:16px;font-family:'Monaco','Consolas',monospace;font-size:13px;color:var(--text-primary);word-break:break-all;position:relative;overflow:hidden}.url-box::before{content:'';position:absolute;top:0;left:0;right:0;height:3px;background:linear-gradient(90deg,var(--primary) 0%,var(--primary-light) 100%)}.button-group{display:flex;gap:12px;margin-top:20px;flex-wrap:wrap}.btn{flex:1;min-width:120px;padding:12px 20px;border-radius:10px;border:none;font-size:14px;font-weight:600;cursor:pointer;transition:all .3s ease;display:inline-flex;align-items:center;justify-content:center;gap:6px}.btn-primary{background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;box-shadow:0 4px 14px rgba(37,99,235,0.3)}.btn-primary:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(37,99,235,0.4)}.btn-secondary{background:#fff;color:var(--primary);border:2px solid var(--border-color)}.btn-secondary:hover{transform:translateY(-2px);box-shadow:var(--shadow-lg)}.btn-success{background:linear-gradient(135deg,#10b981 0%,#34d399 100%);color:#fff;box-shadow:0 4px 14px rgba(16,185,129,0.3)}.btn-success:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(16,185,129,0.4)}.btn-danger{background:linear-gradient(135deg,#ef4444 0%,#f87171 100%);color:#fff}.btn-danger:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(239,68,68,0.4)}.form-group{margin-bottom:20px}label{display:block;margin-bottom:8px;font-weight:600;color:var(--text-primary)}input[type="text"],input[type="number"]{width:100%;padding:12px 16px;border:2px solid var(--border-color);border-radius:10px;background:#fff;color:var(--text-primary);font-size:14px;box-sizing:border-box;transition:all .3s ease}input[type="text"]:focus,input[type="number"]:focus{outline:none;border-color:var(--primary);box-shadow:0 0 0 3px rgba(37,99,235,0.1)}.input-group{display:flex;gap:8px}.input-group input{flex:1}.input-group .btn{flex:none;min-width:auto;padding:10px 16px;font-size:13px}.list{display:flex;flex-direction:column;gap:8px;margin-bottom:12px}.list-item{display:flex;gap:8px;align-items:center}.list-item input{flex:1}.list-item .btn{flex:none;min-width:auto;padding:8px 12px;font-size:12px}.chip{padding:6px 14px;font-size:12px;min-width:auto}.link-arrow{color:var(--primary);text-decoration:none;font-size:14px;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;border-radius:8px;background:var(--bg-gradient-end);transition:all .3s ease;margin-left:8px}.link-arrow:hover{background:var(--primary);color:#fff}.label-with-link{display:flex;align-items:center}.config-section{display:none}.config-section.active{display:block}.collapse-section{margin-bottom:16px;border:2px solid var(--border-color);border-radius:12px;overflow:hidden}.collapse-header{width:100%;padding:16px 20px;background:linear-gradient(135deg,var(--bg-gradient-start) 0%,var(--bg-gradient-end) 100%);border:none;cursor:pointer;display:flex;align-items:center;justify-content:space-between;font-size:16px;font-weight:600;color:var(--text-primary);transition:all .3s ease}.collapse-header:hover{background:linear-gradient(135deg,var(--bg-gradient-end) 0%,var(--bg-gradient-start) 100%)}.collapse-header .icon{font-size:20px;transition:transform .3s ease}.collapse-header.active .icon{transform:rotate(180deg)}.collapse-content{max-height:0;overflow:hidden;transition:max-height .3s ease,padding .3s ease;padding:0 20px}.collapse-content.active{max-height:2000px;padding:20px}.qr-modal{display:none;position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(30,58,95,0.6);backdrop-filter:blur(4px);z-index:1000;align-items:center;justify-content:center;padding:20px}.qr-modal.active{display:flex}.qr-content{background:var(--card-bg);border-radius:24px;padding:32px;text-align:center;max-width:400px;width:100%;box-shadow:var(--shadow-lg);border:1px solid var(--border-color);position:relative}.qr-content::before{content:'';position:absolute;top:0;left:0;right:0;height:6px;background:linear-gradient(90deg,var(--primary) 0%,var(--primary-light) 100%);border-radius:24px 24px 0 0}.qr-title{font-size:20px;font-weight:600;color:var(--text-primary);margin-bottom:8px}.qr-subtitle{color:var(--text-secondary);font-size:14px;margin-bottom:20px}#qrCanvas{display:flex;justify-content:center;margin:20px 0;padding:20px;background:#fff;border-radius:16px;border:2px solid var(--border-color)}.qr-close{background:linear-gradient(135deg,var(--primary) 0%,var(--primary-light) 100%);color:#fff;border:none;padding:12px 32px;border-radius:10px;font-weight:600;cursor:pointer;transition:all .3s ease}.qr-close:hover{transform:translateY(-2px);box-shadow:0 4px 14px rgba(37,99,235,0.3)}.toast{position:fixed;bottom:24px;left:50%;transform:translateX(-50%) translateY(100px);background:var(--text-primary);color:#fff;padding:12px 24px;border-radius:10px;font-size:14px;opacity:0;transition:all .3s ease;z-index:2000}.toast.show{transform:translateX(-50%) translateY(0);opacity:1}.message{margin-top:12px;padding:12px 16px;border-radius:10px;text-align:center;font-size:14px;font-weight:500}.message.success{background:#d1fae5;border:1px solid #a7f3d0;color:#065f46}.message.error{background:#fee2e2;border:1px solid #fecaca;color:#991b1b}.spinner{display:inline-block;width:12px;height:12px;border:2px solid rgba(255,255,255,.35);border-top-color:#fff;border-radius:50%;animation:spin .8s linear infinite;margin-right:6px;vertical-align:-2px}@keyframes spin{to{transform:rotate(360deg)}}@media(max-width:640px){.wrap{padding:16px}h1{font-size:24px}.topbar{position:static;justify-content:center;margin-bottom:20px}.btn{min-width:100%;margin-bottom:8px}.tab-nav{overflow-x:auto;flex-wrap:nowrap}.tab-btn{white-space:nowrap}}</style></head><body><div class="wrap"><div class="header"><h1>✨ ZQ-VTS</h1><div class="subtitle">安全、快速、稳定的代理服务</div></div><div class="topbar"><a class="gh" href="https://github.com/BAYUEQI/ZQ-VTS" target="_blank" rel="nofollow noopener" aria-label="GitHub 项目"><svg viewBox="0 0 16 16" width="20" height="20" aria-hidden="true" fill="currentColor"><path d="M8 0C3.58 0 0 3.58 0 8c0 3.54 2.29 6.53 5.47 7.59.4.07.55-.17.55-.38 0-.19-.01-.82-.01-1.49-2.01.37-2.53-.49-2.69-.94-.09-.23-.48-.94-.82-1.13-.28-.15-.68-.52-.01-.53.63-.01 1.08.58 1.23.82.72 1.21 1.87.87 2.33.66.07-.52.28-.87.51-1.07-1.78-.2-3.64-.89-3.64-3.95 0-.87.31-1.59.82-2.15-.08-.2-.36-1.02.08-2.12 0 0 .67-.21 2.2.82.64-.18 1.32-.27 2-.27.68 0 1.36.09 2 .27 1.53-1.04 2.2-.82 2.2-.82.44 1.1.16 1.92.08 2.12.51.56.82 1.27.82 2.15 0 3.07-1.87 3.75-3.65 3.95.29.25.54.73.54 1.48 0 1.07-.01 1.93-.01 2.2 0 .21.15.46.55.38A8.013 8.013 0 0 0 16 8c0-4.42-3.58-8-8-8z"></path></svg></a></div><div class="main-card"><div class="collapse-section"><button class="collapse-header active" data-collapse="sub-content"><span>📡 订阅链接</span><span class="icon">▼</span></button><div class="collapse-content active" id="sub-content"><div class="url-box">${subUrl}</div><div class="button-group"><button class="btn btn-primary copy" data-text="${subUrl}">📋 复制订阅链接</button><button class="btn btn-secondary copy" id="exportNodes">📤 导出节点信息</button><button class="btn btn-success" id="showQrBtn">📱 显示二维码</button></div></div></div><div class="collapse-section"><button class="collapse-header" data-collapse="config-content"><span>⚙️ 配置管理</span><span class="icon">▼</span></button><div class="collapse-content" id="config-content"><form id="configForm"><div class="form-group"><label for="uuid">UUID</label><input type="text" id="uuid" name="uuid" required placeholder="请输入UUID"></div><div class="form-group"><div class="label-with-link"><label>优选IP (可选)</label><a href="https://ipdb.030101.xyz/bestcfv4/" target="_blank" rel="nofollow noopener" class="link-arrow" title="优选IP地址">↗</a></div><div id="domains" class="list"></div><div class="input-group"><input type="text" id="domainNew" placeholder="输入IP后点击添加"><button type="button" id="addDomain" class="btn btn-secondary chip">➕ 添加</button></div></div><div class="form-group"><label>端口 (可选)</label><div id="ports" class="list"></div><div class="input-group"><input type="number" id="portNew" min="1" max="65535" placeholder="输入端口后点击添加"><button type="button" id="addPort" class="btn btn-secondary chip">➕ 添加</button></div></div><div class="form-group"><label for="s5">SOCKS5代理 (可选)</label><div class="input-group"><input type="text" id="s5" name="s5" placeholder="格式: user:pass@host:port 或 host:port"><button type="button" id="probeS5" class="btn btn-secondary chip">🔍 检测</button></div></div><div class="form-group"><div class="label-with-link"><label for="proxyIp">ProxyIP (可选)</label><a href="https://ipdb.030101.xyz/bestproxy/" target="_blank" rel="nofollow noopener" class="link-arrow" title="ProxyIP地址">↗</a></div><div class="input-group"><input type="text" id="proxyIp" name="proxyIp" placeholder="格式: host:port 或 host"><button type="button" id="probeProxy" class="btn btn-secondary chip">🔍 检测</button></div></div><div class="form-group"><label for="password">Trojan密码 (可选)</label><div class="input-group"><input type="text" id="password" name="password" placeholder="设置Trojan协议的密码"></div></div><div class="button-group"><button type="submit" class="btn btn-primary">💾 保存配置</button><button type="button" class="btn btn-secondary" onclick="loadConfig()">🔄 重新加载</button></div><div id="message" class="message" style="display:none"></div></form></div></div></div><div class="qr-modal" id="qrModal"><div class="qr-content"><div class="qr-title">📱 扫码订阅</div><div class="qr-subtitle">使用客户端扫描二维码快速添加</div><div id="qrCanvas"></div><button class="qr-close" id="closeQrBtn">关闭</button></div></div><div class="toast" id="toast"></div><script src="https://cdnjs.cloudflare.com/ajax/libs/qrcodejs/1.0.0/qrcode.min.js"></script><script>(function(){const toastEl=document.getElementById('toast');function showToast(msg){toastEl.textContent=msg;toastEl.classList.add('show');setTimeout(()=>toastEl.classList.remove('show'),2000)}function showMessage(text,type){const el=document.getElementById('message');el.textContent=text;el.className='message '+type;el.style.display='block';setTimeout(()=>{el.style.display='none'},3000)}function fallbackCopy(text){const ta=document.createElement('textarea');ta.value=text;ta.setAttribute('readonly','');ta.style.position='absolute';ta.style.left='-9999px';document.body.appendChild(ta);ta.select();let ok=false;try{ok=document.execCommand('copy')}catch(e){}document.body.removeChild(ta);return ok}async function doCopy(btn){const t=btn.getAttribute('data-text');if(!t)return;let ok=false;if(navigator.clipboard&&navigator.clipboard.writeText){try{await navigator.clipboard.writeText(t);ok=true}catch(e){ok=false}}if(!ok){ok=fallbackCopy(t)}showToast(ok?'✅ 已复制到剪贴板':'❌ 复制失败')}document.querySelectorAll('button.copy').forEach(b=>b.addEventListener('click',e=>{doCopy(e.currentTarget)}));const exportBtn=document.getElementById('exportNodes');if(exportBtn){exportBtn.addEventListener('click',async()=>{const allNodes=${allNodesJson};const nodeText=allNodes.join('\\n')+'\\n';const nodeTextBase64=btoa(unescape(encodeURIComponent(nodeText)));let ok=false;if(navigator.clipboard&&navigator.clipboard.writeText){try{await navigator.clipboard.writeText(nodeTextBase64);ok=true}catch(e){ok=false}}if(!ok){ok=fallbackCopy(nodeTextBase64)}showToast(ok?'✅ 已导出到剪贴板':'❌ 导出失败')})}const showQrBtn=document.getElementById('showQrBtn');const qrModal=document.getElementById('qrModal');const closeQrBtn=document.getElementById('closeQrBtn');const qrCanvas=document.getElementById('qrCanvas');let qrCode=null;showQrBtn.addEventListener('click',()=>{qrModal.classList.add('active');if(!qrCode){qrCode=new QRCode(qrCanvas,{text:'${subUrl}',width:220,height:220,colorDark:'#2563eb',colorLight:'#ffffff',correctLevel:QRCode.CorrectLevel.M})}});closeQrBtn.addEventListener('click',()=>{qrModal.classList.remove('active')});qrModal.addEventListener('click',(e)=>{if(e.target===qrModal)qrModal.classList.remove('active')});const tabBtns=document.querySelectorAll('.tab-btn');const configSections=document.querySelectorAll('.config-section');tabBtns.forEach(btn=>{btn.addEventListener('click',()=>{const tab=btn.dataset.tab;tabBtns.forEach(b=>b.classList.remove('active'));configSections.forEach(s=>s.classList.remove('active'));btn.classList.add('active');document.getElementById(tab+'-section').classList.add('active')})});function renderList(container,values,placeholder,isPort){container.innerHTML='';values.forEach((val,idx)=>{const row=document.createElement('div');row.className='list-item';const input=document.createElement('input');input.type=isPort?'number':'text';if(isPort){input.min='1';input.max='65535'}input.value=String(val);input.placeholder=placeholder;const del=document.createElement('button');del.type='button';del.className='btn btn-danger chip';del.textContent='🗑️ 删除';del.addEventListener('click',()=>{values.splice(idx,1);renderList(container,values,placeholder,isPort)});row.appendChild(input);row.appendChild(del);container.appendChild(row);input.addEventListener('input',()=>{values[idx]=isPort?Number(Math.max(1,Math.min(65535,parseInt(input.value||'0',10)))):input.value.trim()})})}const state={domains:[],ports:[]};async function loadConfig(){try{const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const response=await fetch('/api/config/'+uuid);if(!response.ok)throw 0;const cfg=await response.json();document.getElementById('uuid').value=cfg.uuid||'';document.getElementById('s5').value=cfg.s5||'';document.getElementById('proxyIp').value=cfg.proxyIp||'';document.getElementById('password').value=cfg.password||'';state.domains=Array.isArray(cfg.domains)?cfg.domains.slice():[];if((cfg.domain||'').trim())state.domains.unshift(cfg.domain.trim());state.domains=[...new Set(state.domains.filter(Boolean))];state.ports=(Array.isArray(cfg.ports)?cfg.ports:[]).map(x=>parseInt(x,10)).filter(n=>n>0&&n<=65535);if(parseInt(cfg.port,10))state.ports.unshift(parseInt(cfg.port,10));state.ports=[...new Set(state.ports)];renderList(document.getElementById('domains'),state.domains,'如: example.com 或 127.0.0.1',false);renderList(document.getElementById('ports'),state.ports,'如: 443',true);showMessage('✅ 配置加载成功','success')}catch(e){showMessage('❌ 配置加载失败','error')}}async function saveConfigForm(){const uuid=document.getElementById('uuid').value.trim();const s5=document.getElementById('s5').value.trim();const proxyIp=document.getElementById('proxyIp').value.trim();const password=document.getElementById('password').value.trim();const domains=Array.from(document.querySelectorAll('#domains .list-item input')).map(i=>i.value.trim()).filter(Boolean);const ports=Array.from(document.querySelectorAll('#ports .list-item input')).map(i=>parseInt(i.value,10)).filter(n=>n>0&&n<=65535);const body={uuid,s5,proxyIp,password,domains,ports};const response=await fetch('/api/config/'+uuid,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify(body)});const result=await response.json();if(response.ok){showMessage('✅ '+(result.message||'配置保存成功'),'success');setTimeout(()=>{window.location.href='/'+uuid;},800);}else{showMessage('❌ '+(result.error||'配置保存失败'),'error')}}document.addEventListener('DOMContentLoaded',()=>{const collapseHeaders=document.querySelectorAll('.collapse-header');collapseHeaders.forEach(header=>{header.addEventListener('click',()=>{const targetId=header.getAttribute('data-collapse');const content=document.getElementById(targetId);const isActive=header.classList.contains('active');if(isActive){header.classList.remove('active');content.classList.remove('active')}else{header.classList.add('active');content.classList.add('active')}})});const s5Btn=document.getElementById('probeS5');const pxBtn=document.getElementById('probeProxy');const addDomain=document.getElementById('addDomain');const addPort=document.getElementById('addPort');const domainNew=document.getElementById('domainNew');const portNew=document.getElementById('portNew');addDomain&&addDomain.addEventListener('click',()=>{const v=(domainNew.value||'').trim();if(!v)return;state.domains.push(v);renderList(document.getElementById('domains'),state.domains,'如: example.com',false);domainNew.value=''});addPort&&addPort.addEventListener('click',()=>{const n=parseInt(portNew.value||'0',10);if(!n||n<1||n>65535)return;state.ports.push(n);renderList(document.getElementById('ports'),state.ports,'如: 443',true);portNew.value=''});const runProbe=async(btn,url,label)=>{if(!btn)return;btn.disabled=true;btn.innerHTML='<span class="spinner"></span>'+label;let res;try{const r=await fetch(url);res=await r.json()}catch{res={ok:false,message:'接口错误'}}btn.disabled=false;btn.innerHTML='🔍 检测';return res};if(s5Btn){s5Btn.addEventListener('click',async(e)=>{e.preventDefault();const timeout=1000;const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const valEl=document.getElementById('s5');const val=(valEl&&valEl.value||'').trim();const q='&uuid='+encodeURIComponent(uuid)+(val?('&s5='+encodeURIComponent(val)):'');const res=await runProbe(s5Btn,'/api/probe?type=s5&timeout='+timeout+q,'检测中');showMessage((res.ok?'✅':'❌')+' SOCKS5：'+(res.ok?'可用':'不可用')+' ('+(res.ms||'-')+'ms) '+(res.message||''),res.ok?'success':'error')})}if(pxBtn){pxBtn.addEventListener('click',async(e)=>{e.preventDefault();const timeout=1000;const uuid=document.getElementById('uuid').value.trim()||'${userUUID}';const valEl=document.getElementById('proxyIp');const val=(valEl&&valEl.value||'').trim();const q='&uuid='+encodeURIComponent(uuid)+(val?('&proxyip='+encodeURIComponent(val)):'');const res=await runProbe(pxBtn,'/api/probe?type=proxyip&timeout='+timeout+q,'检测中');showMessage((res.ok?'✅':'❌')+' ProxyIP：'+(res.ok?'可用':'不可用')+' ('+(res.ms||'-')+'ms) '+(res.message||''),res.ok?'success':'error')})}});document.getElementById('configForm').addEventListener('submit',function(e){e.preventDefault();saveConfigForm()});loadConfig()})()</script></body></html>`;
			return new Response(html, {headers:{'content-type':'text/html; charset=utf-8'}});
		}
		return new Response('Not Found', { status: 404 });
	}
};
