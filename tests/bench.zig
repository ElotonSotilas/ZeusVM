const std = @import("std");

pub fn main() !void {
    var timer = try std.time.Timer.start();
    const start = timer.read();

    const iterations: u64 = 10000000;
    var sum: f64 = 0.0;
    var i: u64 = 0;
    while (i < iterations) {
        i += 1;
        sum += @sqrt(@as(f64, @floatFromInt(i)));
    }

    const end = timer.read();
    const elapsed = end - start;

    std.debug.print("Native Zig: {d}ms (Sum: {d})\n", .{ elapsed / 1000000, sum });
}
