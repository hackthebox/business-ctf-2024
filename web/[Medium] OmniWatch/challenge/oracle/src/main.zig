const std = @import("std");
const httpz = @import("httpz");

const DefaultPrng = std.rand.DefaultPrng;
const Allocator = std.mem.Allocator;

var rand_impl = DefaultPrng.init(1);

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();
    const t1 = try std.Thread.spawn(.{}, start, .{allocator});
    t1.join();
}

pub fn start(allocator: Allocator) !void {
    var server = try httpz.Server().init(allocator, .{ .address = "0.0.0.0", .port = 4000 });
    defer server.deinit();
    var router = server.router();

    server.notFound(notFound);

    router.get("/oracle/:mode/:deviceId", oracle);
    try server.listen();
}

fn randomCoordinates() ![]const u8 {
    const strings = [_][]const u8{
        "37.8245", "-34.6037", "-122.4374", "-58.3816", "151.2093",
    };

    const randomIndex = @mod(rand_impl.random().int(u32), strings.len);
    const randomString = strings[randomIndex];
    return randomString;
}

fn oracle(req: *httpz.Request, res: *httpz.Response) !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    const allocator = gpa.allocator();

    const deviceId = req.param("deviceId").?;
    const mode = req.param("mode").?;
    const decodedDeviceId = try std.Uri.unescapeString(allocator, deviceId);
    const decodedMode = try std.Uri.unescapeString(allocator, mode);

    const latitude = try randomCoordinates();
    const longtitude = try randomCoordinates();

    res.header("X-Content-Type-Options", "nosniff");
    res.header("X-XSS-Protection", "1; mode=block");
    res.header("DeviceId", decodedDeviceId);

    if (std.mem.eql(u8, decodedMode, "json")) {
        try res.json(.{ .lat = latitude, .lon = longtitude }, .{});
    } else {
        const htmlTemplate =
            \\<!DOCTYPE html>
            \\<html>
            \\    <head>
            \\        <title>Device Oracle API v2.6</title>
            \\    </head>
            \\<body>
            \\    <p>Mode: {s}</p><p>Lat: {s}</p><p>Lon: {s}</p>
            \\</body>
            \\</html>
        ;

        res.body = try std.fmt.allocPrint(res.arena, htmlTemplate, .{ decodedMode, latitude, longtitude });
    }
}

fn notFound(_: *httpz.Request, res: *httpz.Response) !void {
    res.status = 404;
    res.body = "Not found";
}
