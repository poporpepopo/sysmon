// CPU・メモリ・ネットワーク速度をメニューバーに常時表示する。
// クリックすると直近2分の推移と内訳を出す。
import AppKit
import Darwin

let host = mach_host_self()
let historyLength = 120
let loginAgentLabel = "io.github.poporpepopo.sysmon"
let loginAgentPath = NSString(string: "~/Library/LaunchAgents/\(loginAgentLabel).plist").expandingTildeInPath

// MARK: - 計測

struct CPUUsage {
    var user: Double
    var system: Double
    var total: Double { user + system }
}

final class CPUSampler {
    private var prev: [UInt32]?

    // 前回呼び出しからの差分で使用率を出すので、初回は nil
    func sample() -> CPUUsage? {
        var info = host_cpu_load_info()
        var count = mach_msg_type_number_t(MemoryLayout<host_cpu_load_info>.size / MemoryLayout<integer_t>.size)
        let kr = withUnsafeMutablePointer(to: &info) {
            $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
                host_statistics(host, HOST_CPU_LOAD_INFO, $0, &count)
            }
        }
        guard kr == KERN_SUCCESS else { return nil }
        let t = info.cpu_ticks
        let now = [t.0, t.1, t.2, t.3] // user, system, idle, nice
        defer { prev = now }
        guard let p = prev else { return nil }
        let d = zip(now, p).map { Double($0 &- $1) }
        let all = d.reduce(0, +)
        guard all > 0 else { return nil }
        return CPUUsage(user: (d[0] + d[3]) / all, system: d[1] / all)
    }
}

struct MemoryUsage {
    var used: UInt64
    var total: UInt64
    var compressed: UInt64
    var swap: UInt64
    var ratio: Double { Double(used) / Double(total) }
}

func sampleMemory() -> MemoryUsage? {
    var vm = vm_statistics64()
    var count = mach_msg_type_number_t(MemoryLayout<vm_statistics64>.size / MemoryLayout<integer_t>.size)
    let kr = withUnsafeMutablePointer(to: &vm) {
        $0.withMemoryRebound(to: integer_t.self, capacity: Int(count)) {
            host_statistics64(host, HOST_VM_INFO64, $0, &count)
        }
    }
    guard kr == KERN_SUCCESS else { return nil }
    var pageSize: vm_size_t = 0
    host_page_size(host, &pageSize)
    let page = UInt64(pageSize)
    // アクティビティモニタの「使用済みメモリ」と同じ数え方: Appメモリ + 確保されているメモリ + 圧縮
    let anon = UInt64(vm.internal_page_count), purgeable = UInt64(vm.purgeable_count)
    let app = anon > purgeable ? anon - purgeable : 0
    let wired = UInt64(vm.wire_count), compressed = UInt64(vm.compressor_page_count)
    var swap = xsw_usage()
    var size = MemoryLayout<xsw_usage>.size
    sysctlbyname("vm.swapusage", &swap, &size, nil, 0)
    return MemoryUsage(used: (app + wired + compressed) * page,
                       total: ProcessInfo.processInfo.physicalMemory,
                       compressed: compressed * page,
                       swap: swap.xsu_used)
}

final class NetSampler {
    private var prev: (rx: UInt64, tx: UInt64, at: TimeInterval)?

    // バイト/秒。初回は nil
    func sample() -> (rx: Double, tx: Double)? {
        let now = Self.totalBytes()
        let at = ProcessInfo.processInfo.systemUptime
        defer { prev = (now.rx, now.tx, at) }
        guard let p = prev, at > p.at else { return nil }
        let dt = at - p.at
        // インターフェースが消えるとカウンタの合計が減るので、その回は 0 とする
        let rx = now.rx >= p.rx ? Double(now.rx - p.rx) / dt : 0
        let tx = now.tx >= p.tx ? Double(now.tx - p.tx) / dt : 0
        return (rx, tx)
    }

    // 物理インターフェース（en*: Wi-Fi・有線・USB/Thunderbolt）の累計バイト数。
    // utun（VPN）や lo0 を足すと同じ通信を二重に数えてしまうので除く。
    // getifaddrs の if_data は 32bit で 4GB で一周するため、64bit の NET_RT_IFLIST2 を使う。
    static func totalBytes() -> (rx: UInt64, tx: UInt64) {
        var mib: [Int32] = [CTL_NET, PF_ROUTE, 0, 0, NET_RT_IFLIST2, 0]
        var len = 0
        guard sysctl(&mib, 6, nil, &len, nil, 0) == 0, len > 0 else { return (0, 0) }
        var buf = [UInt8](repeating: 0, count: len)
        guard sysctl(&mib, 6, &buf, &len, nil, 0) == 0 else { return (0, 0) }
        var rx: UInt64 = 0, tx: UInt64 = 0
        buf.withUnsafeBytes { raw in
            var off = 0
            while off + 4 <= len {
                let msglen = Int(raw.loadUnaligned(fromByteOffset: off, as: UInt16.self))
                let type = raw[off + 3]
                if msglen == 0 { break }
                if Int32(type) == RTM_IFINFO2, off + MemoryLayout<if_msghdr2>.size <= len {
                    let m = raw.loadUnaligned(fromByteOffset: off, as: if_msghdr2.self)
                    var name = [CChar](repeating: 0, count: Int(IF_NAMESIZE) + 1)
                    if if_indextoname(UInt32(m.ifm_index), &name) != nil,
                       String(cString: name).hasPrefix("en") {
                        rx += m.ifm_data.ifi_ibytes
                        tx += m.ifm_data.ifi_obytes
                    }
                }
                off += msglen
            }
        }
        return (rx, tx)
    }
}

// MARK: - 表示用

func formatRate(_ bytesPerSec: Double) -> String {
    let units = ["B/s", "KB/s", "MB/s", "GB/s"]
    var v = bytesPerSec, i = 0
    while v >= 999.5 && i < units.count - 1 { v /= 1000; i += 1 }
    if i == 0 { return "\(Int(v.rounded())) B/s" }
    return v < 9.95 ? String(format: "%.1f %@", v, units[i]) : String(format: "%.0f %@", v, units[i])
}

func formatMbps(_ bytesPerSec: Double) -> String {
    let mbps = bytesPerSec * 8 / 1_000_000
    // 1 Mbps 未満でも 0.0 に潰れないよう、小さいほど桁を増やす
    if mbps < 0.995 { return String(format: "%.2f Mbps", mbps) }
    return mbps < 9.95 ? String(format: "%.1f Mbps", mbps) : String(format: "%.0f Mbps", mbps)
}

func formatBytes(_ bytes: UInt64) -> String {
    let f = ByteCountFormatter()
    f.countStyle = .memory
    f.allowsNonnumericFormatting = false // 0 のとき「Zero KB」にしない
    return f.string(fromByteCount: Int64(bytes))
}

func levelColor(_ ratio: Double) -> NSColor {
    ratio < 0.6 ? .systemGreen : ratio < 0.85 ? .systemOrange : .systemRed
}

let downColor = NSColor.systemBlue
let upColor = NSColor.systemOrange

final class Model {
    var cpu = CPUUsage(user: 0, system: 0)
    var mem: MemoryUsage?
    var rx = 0.0, tx = 0.0
    var cpuHist: [Double] = [], memHist: [Double] = [], rxHist: [Double] = [], txHist: [Double] = []

    private let cpuSampler = CPUSampler()
    private let netSampler = NetSampler()

    init() {
        _ = cpuSampler.sample()
        _ = netSampler.sample()
    }

    func update() {
        if let c = cpuSampler.sample() { cpu = c }
        mem = sampleMemory()
        if let n = netSampler.sample() { rx = n.rx; tx = n.tx }
        push(&cpuHist, cpu.total)
        push(&memHist, mem?.ratio ?? 0)
        push(&rxHist, rx)
        push(&txHist, tx)
    }

    private func push(_ a: inout [Double], _ v: Double) {
        a.append(v)
        if a.count > historyLength { a.removeFirst(a.count - historyLength) }
    }
}

// メニューバーの画像。macOS 26 のメニューバーは文字色を無視して単色にするので、
// 色付きのゲージを出すには isTemplate=false の画像を描くしかない。
// 文字色は描画時に解決される labelColor を使い、明るい/暗いメニューバーの両方に追従させる。
// ゲーミングモードの演出の状態。load は CPU 使用率をなめらかにしたもの（0〜1）
struct Effects {
    var on = false
    var load = 0.0
    var phase = 0.0 // 虹色のずれ（0〜1 で一周）
    var time = 0.0
}

// 横方向に色相が一周する虹色のグラデーション。phase で全体をずらす
func rainbow(_ phase: Double, alpha: CGFloat, saturation: CGFloat = 0.85, brightness: CGFloat = 1) -> NSGradient {
    let n = 7
    let colors = (0..<n).map { i -> NSColor in
        let h = (phase + Double(i) / Double(n - 1)).truncatingRemainder(dividingBy: 1)
        return NSColor(hue: CGFloat(h), saturation: saturation, brightness: brightness, alpha: alpha)
    }
    return NSGradient(colors: colors)!
}

func statusImage(_ m: Model, _ fx: Effects = Effects()) -> NSImage {
    let labelFont = NSFont.systemFont(ofSize: 8, weight: .semibold)
    let valueFont = NSFont.monospacedDigitSystemFont(ofSize: 10, weight: .semibold)
    let netFont = NSFont.monospacedDigitSystemFont(ofSize: 9.5, weight: .medium)
    func width(_ s: String, _ f: NSFont) -> CGFloat {
        ceil((s as NSString).size(withAttributes: [.font: f]).width)
    }

    let height: CGFloat = 22, barW: CGFloat = 4, barH: CGFloat = 16, gap: CGFloat = 3, spacing: CGFloat = 8
    // 値が変わってもメニューバーの幅が揺れないよう、最大幅で固定する
    let colW = max(width("100%", valueFont), width("MEM", labelFont))
    let gaugeW = barW + gap + colW
    let arrowW = width("↓", netFont) + 1
    let rateW = width("1000 Mbps", netFont)
    let netW = arrowW + rateW
    // ゲーミングモードでは背景の光を見せるため左右に余白を取る
    let pad: CGFloat = fx.on ? 5 : 0
    let size = NSSize(width: gaugeW * 2 + spacing * 2 + netW + pad * 2, height: height)

    let cpu = m.cpu.total, mem = m.mem?.ratio ?? 0, rx = m.rx, tx = m.tx
    let img = NSImage(size: size, flipped: false) { _ in
        if fx.on { drawGamingBackground(size: size, fx: fx) }
        // 80% を超えたら脈打ち、90% を超えたら中身を小刻みに震わせる
        let shake = max(0, (fx.load - 0.9) / 0.1)
        let t = NSAffineTransform()
        t.translateX(by: pad + CGFloat.random(in: -1...1) * shake * 1.2,
                     yBy: CGFloat.random(in: -1...1) * shake * 0.8)
        t.concat()

        func bar(x: CGFloat, ratio: Double) {
            let track = NSRect(x: x, y: (height - barH) / 2, width: barW, height: barH)
            NSColor.tertiaryLabelColor.setFill()
            NSBezierPath(roundedRect: track, xRadius: 1.5, yRadius: 1.5).fill()
            var fill = track
            fill.size.height = max(1.5, barH * CGFloat(min(max(ratio, 0), 1)))
            let fillPath = NSBezierPath(roundedRect: fill, xRadius: 1.5, yRadius: 1.5)
            if fx.on {
                // ゲージの中身も縦方向に虹色を流す
                rainbow(fx.phase + Double(x) / 100, alpha: 1).draw(in: fillPath, angle: 90)
            } else {
                levelColor(ratio).setFill()
                fillPath.fill()
            }
        }
        bar(x: 0, ratio: cpu)
        bar(x: gaugeW + spacing, ratio: mem)

        let nx = (gaugeW + spacing) * 2
        let right = NSMutableParagraphStyle()
        right.alignment = .right
        func drawTexts() {
            for (x, ratio, label) in [(CGFloat(0), cpu, "CPU"), (gaugeW + spacing, mem, "MEM")] {
                let tx = x + barW + gap
                NSAttributedString(string: label, attributes: [
                    .font: labelFont, .foregroundColor: NSColor.labelColor.withAlphaComponent(0.75),
                ]).draw(at: NSPoint(x: tx, y: 11))
                NSAttributedString(string: "\(Int((ratio * 100).rounded()))%", attributes: [
                    .font: valueFont, .foregroundColor: NSColor.labelColor,
                ]).draw(at: NSPoint(x: tx, y: -0.5))
            }
            for (y, arrow, color, rate) in [(CGFloat(10.5), "↑", upColor, tx), (-0.5, "↓", downColor, rx)] {
                NSAttributedString(string: arrow, attributes: [.font: netFont, .foregroundColor: color])
                    .draw(at: NSPoint(x: nx, y: y))
                NSAttributedString(string: formatMbps(rate), attributes: [
                    .font: netFont, .foregroundColor: NSColor.labelColor, .paragraphStyle: right,
                ]).draw(in: NSRect(x: nx + arrowW, y: y, width: rateW, height: 12))
            }
        }

        guard fx.on, let ctx = NSGraphicsContext.current?.cgContext else {
            drawTexts()
            return true
        }
        // ゲーミングモードでは、文字を透明レイヤーに描いてから文字の形だけに虹色を流し込む（.sourceIn）。
        // 背景と同じ色が重なると文字が消えるので、色相を半周ずらした補色にする。
        // 影はレイヤー全体に付け、背景が濃くなっても文字が埋もれないようにする
        let dark = NSAppearance.currentDrawing().bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
        ctx.saveGState()
        let shadow = NSShadow()
        shadow.shadowColor = (dark ? NSColor.black : NSColor.white).withAlphaComponent(0.5 + 0.5 * fx.load)
        shadow.shadowBlurRadius = 1.5
        shadow.shadowOffset = .zero
        shadow.set()
        ctx.beginTransparencyLayer(auxiliaryInfo: nil)
        drawTexts()
        ctx.setBlendMode(.sourceIn)
        rainbow(fx.phase + 0.5, alpha: 1, saturation: dark ? 0.35 : 0.9, brightness: dark ? 1 : 0.45)
            .draw(in: NSRect(x: -pad, y: 0, width: size.width, height: height), angle: 0)
        ctx.endTransparencyLayer()
        ctx.restoreGState()
        return true
    }
    img.isTemplate = false
    img.accessibilityDescription = "CPU \(Int(cpu * 100))%、メモリ \(Int(mem * 100))%、受信 \(formatMbps(rx))、送信 \(formatMbps(tx))"
    return img
}

// 負荷が上がるほど濃く、速く流れる虹色の背景。80% を超えると縁が脈打って光る
func drawGamingBackground(size: NSSize, fx: Effects) {
    let rect = NSRect(x: 0.75, y: 1.5, width: size.width - 1.5, height: size.height - 3)
    let path = NSBezierPath(roundedRect: rect, xRadius: 6, yRadius: 6)
    let hot = max(0, (fx.load - 0.8) / 0.2)
    // 脈打つ速さも負荷に比例させる（80% で毎秒2回、100% で毎秒8回）
    let pulse = hot > 0 ? 0.5 + 0.5 * sin(fx.time * 2 * .pi * (2 + 6 * hot)) : 0
    let alpha = CGFloat(0.12 + 0.5 * fx.load + 0.2 * hot * pulse)
    let dark = NSAppearance.currentDrawing().bestMatch(from: [.darkAqua, .aqua]) == .darkAqua
    // 色相が補色でも明るさが近いと文字が読めないので、文字（淡い色）より背景を暗くしておく
    rainbow(fx.phase, alpha: alpha, brightness: dark ? 0.72 : 1).draw(in: path, angle: 0)

    guard let ctx = NSGraphicsContext.current?.cgContext else { return }
    let edge = 0.25 + 0.75 * fx.load
    ctx.saveGState()
    ctx.addPath(path.cgPath.copy(strokingWithWidth: 1 + 1.5 * hot, lineCap: .round, lineJoin: .round, miterLimit: 1))
    ctx.clip()
    rainbow(fx.phase + 0.5, alpha: CGFloat(edge * (hot > 0 ? 0.6 + 0.4 * pulse : 0.6))).draw(in: rect, angle: 0)
    ctx.restoreGState()
}

// メニューを開いたときの詳細表示（数値の内訳と直近2分のグラフ）
final class DetailView: NSView {
    let model: Model
    static let width: CGFloat = 320
    static let pad: CGFloat = 14
    static let sectionH: CGFloat = 78

    init(model: Model) {
        self.model = model
        super.init(frame: NSRect(x: 0, y: 0, width: Self.width, height: 10 + Self.sectionH * 3 + 4))
    }

    required init?(coder: NSCoder) { fatalError() }

    override var isFlipped: Bool { true }

    override func draw(_ dirtyRect: NSRect) {
        let m = model
        var y: CGFloat = 10

        let memText: String, memSub: String
        if let mem = m.mem {
            memText = "\(Int((mem.ratio * 100).rounded()))%"
            memSub = "\(formatBytes(mem.used)) / \(formatBytes(mem.total))　圧縮 \(formatBytes(mem.compressed))　スワップ \(formatBytes(mem.swap))"
        } else {
            memText = "—"; memSub = ""
        }

        section(y: y, title: "CPU", value: "\(Int((m.cpu.total * 100).rounded()))%", valueColor: levelColor(m.cpu.total),
                sub: "ユーザー \(Int((m.cpu.user * 100).rounded()))%　システム \(Int((m.cpu.system * 100).rounded()))%",
                series: [(m.cpuHist, levelColor(m.cpu.total))], scale: 1, scaleLabel: nil)
        y += Self.sectionH
        section(y: y, title: "メモリ", value: memText, valueColor: levelColor(m.mem?.ratio ?? 0), sub: memSub,
                series: [(m.memHist, levelColor(m.mem?.ratio ?? 0))], scale: 1, scaleLabel: nil)
        y += Self.sectionH
        // 小さい揺れでグラフが振り切れないよう、目盛りの最小値を 1 Mbps にする
        let peak = max(125_000, (m.rxHist + m.txHist).max() ?? 0)
        section(y: y, title: "ネットワーク", value: "↓ \(formatMbps(m.rx))  ↑ \(formatMbps(m.tx))", valueColor: .labelColor,
                sub: "↓ \(formatRate(m.rx))　↑ \(formatRate(m.tx))",
                series: [(m.rxHist, downColor), (m.txHist, upColor)], scale: peak, scaleLabel: "最大 \(formatMbps(peak))")
    }

    private func section(y: CGFloat, title: String, value: String, valueColor: NSColor, sub: String,
                         series: [([Double], NSColor)], scale: Double, scaleLabel: String?) {
        let pad = Self.pad, w = Self.width - pad * 2
        NSAttributedString(string: title, attributes: [
            .font: NSFont.systemFont(ofSize: 13, weight: .semibold), .foregroundColor: NSColor.labelColor,
        ]).draw(at: NSPoint(x: pad, y: y))
        let right = NSMutableParagraphStyle()
        right.alignment = .right
        NSAttributedString(string: value, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 13, weight: .semibold),
            .foregroundColor: valueColor, .paragraphStyle: right,
        ]).draw(in: NSRect(x: pad, y: y, width: w, height: 18))
        NSAttributedString(string: sub, attributes: [
            .font: NSFont.monospacedDigitSystemFont(ofSize: 11, weight: .regular),
            .foregroundColor: NSColor.secondaryLabelColor,
        ]).draw(at: NSPoint(x: pad, y: y + 18))

        let g = NSRect(x: pad, y: y + 36, width: w, height: 32)
        NSColor.quaternaryLabelColor.setFill()
        NSBezierPath(roundedRect: g, xRadius: 4, yRadius: 4).fill()
        NSGraphicsContext.saveGraphicsState()
        NSBezierPath(roundedRect: g, xRadius: 4, yRadius: 4).addClip()
        let step = g.width / CGFloat(historyLength - 1)
        for (values, color) in series where values.count > 1 {
            // 最新の値を右端に置き、左へ遡る
            let x0 = g.maxX - step * CGFloat(values.count - 1)
            let pts = values.enumerated().map { i, v in
                NSPoint(x: x0 + step * CGFloat(i), y: g.maxY - g.height * CGFloat(min(v / scale, 1)))
            }
            let area = NSBezierPath()
            area.move(to: NSPoint(x: pts[0].x, y: g.maxY))
            pts.forEach { area.line(to: $0) }
            area.line(to: NSPoint(x: pts.last!.x, y: g.maxY))
            area.close()
            color.withAlphaComponent(0.25).setFill()
            area.fill()
            let stroke = NSBezierPath()
            stroke.move(to: pts[0])
            pts.dropFirst().forEach { stroke.line(to: $0) }
            stroke.lineWidth = 1.2
            color.setStroke()
            stroke.stroke()
        }
        NSGraphicsContext.restoreGraphicsState()
        if let scaleLabel {
            NSAttributedString(string: scaleLabel, attributes: [
                .font: NSFont.systemFont(ofSize: 9), .foregroundColor: NSColor.secondaryLabelColor,
            ]).draw(at: NSPoint(x: g.minX + 4, y: g.minY + 2))
        }
    }
}

// MARK: - アプリ

final class App: NSObject, NSApplicationDelegate {
    var item: NSStatusItem!
    let model = Model()
    var detail: DetailView!
    var loginItem: NSMenuItem!
    var gamingItem: NSMenuItem!
    var fx = Effects()
    var fxTimer: Timer?
    var lastFrame = 0.0, lastRender = 0.0

    func applicationDidFinishLaunching(_ notification: Notification) {
        // 二重起動するとメニューバーに2つ並ぶので、後から起動した方は終了する
        if let id = Bundle.main.bundleIdentifier,
           NSRunningApplication.runningApplications(withBundleIdentifier: id).count > 1 {
            NSApp.terminate(nil)
            return
        }

        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        detail = DetailView(model: model)

        let menu = NSMenu()
        let detailItem = NSMenuItem()
        detailItem.view = detail
        menu.addItem(detailItem)
        menu.addItem(.separator())
        menu.addItem(withTitle: "アクティビティモニタを開く", action: #selector(openActivityMonitor), keyEquivalent: "").target = self
        gamingItem = menu.addItem(withTitle: "ゲーミングモード", action: #selector(toggleGaming), keyEquivalent: "")
        gamingItem.target = self
        loginItem = menu.addItem(withTitle: "ログイン時に起動", action: #selector(toggleLogin), keyEquivalent: "")
        loginItem.target = self
        menu.addItem(.separator())
        menu.addItem(withTitle: "終了", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.menu = menu
        updateLoginState()
        setGaming(UserDefaults.standard.bool(forKey: "gamingMode"))

        tick()
        // メニューを開いている間（イベントトラッキング中）も更新が止まらないよう .common に載せる
        let timer = Timer(timeInterval: 1, repeats: true) { [weak self] _ in self?.tick() }
        RunLoop.main.add(timer, forMode: .common)
    }

    func tick() {
        model.update()
        // ゲーミングモード中はアニメーション側で毎フレーム描く
        if !fx.on { item.button?.image = statusImage(model) }
        detail.needsDisplay = true
    }

    @objc func toggleGaming() {
        setGaming(!fx.on)
        UserDefaults.standard.set(fx.on, forKey: "gamingMode")
    }

    func setGaming(_ on: Bool) {
        fx.on = on
        gamingItem.state = on ? .on : .off
        fxTimer?.invalidate()
        fxTimer = nil
        if on {
            lastFrame = ProcessInfo.processInfo.systemUptime
            let t = Timer(timeInterval: 1.0 / 30, repeats: true) { [weak self] _ in self?.frame() }
            RunLoop.main.add(t, forMode: .common)
            fxTimer = t
        } else {
            item.button?.image = statusImage(model)
        }
    }

    // 30fps で回し、負荷に応じて描き直す頻度を変える（暇なときは毎秒8回、全開で毎秒30回）。
    // 1秒ごとの計測値の間はなめらかに補間して、色の流れが急に変わらないようにする
    func frame() {
        let now = ProcessInfo.processInfo.systemUptime
        let dt = now - lastFrame
        lastFrame = now
        fx.load += (model.cpu.total - fx.load) * min(1, dt * 2.5)
        fx.phase = (fx.phase + dt * (0.04 + 1.6 * pow(fx.load, 1.5))).truncatingRemainder(dividingBy: 1)
        fx.time = now
        guard now - lastRender >= 1 / (8 + 22 * fx.load) - 0.001 else { return }
        lastRender = now
        item.button?.image = statusImage(model, fx)
    }

    @objc func openActivityMonitor() {
        NSWorkspace.shared.open(URL(fileURLWithPath: "/System/Applications/Utilities/Activity Monitor.app"))
    }

    func updateLoginState() {
        loginItem.state = FileManager.default.fileExists(atPath: loginAgentPath) ? .on : .off
    }

    // LaunchAgent の plist を置く/消すだけ。反映は次回ログインから
    // （ここで launchctl bootstrap すると RunAtLoad で2つ目が起動してしまう）
    @objc func toggleLogin() {
        if FileManager.default.fileExists(atPath: loginAgentPath) {
            try? FileManager.default.removeItem(atPath: loginAgentPath)
        } else if let exe = Bundle.main.executablePath {
            let plist: [String: Any] = [
                "Label": loginAgentLabel,
                "ProgramArguments": [exe],
                "RunAtLoad": true,
            ]
            try? FileManager.default.createDirectory(atPath: (loginAgentPath as NSString).deletingLastPathComponent,
                                                     withIntermediateDirectories: true)
            (plist as NSDictionary).write(toFile: loginAgentPath, atomically: true)
        }
        updateLoginState()
    }
}

let app = NSApplication.shared
let delegate = App()
app.delegate = delegate
app.setActivationPolicy(.accessory)
app.run()
