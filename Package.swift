// swift-tools-version:4.0
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "cURL",
    pkgConfig: "curl",
    providers: [
        .brew(["curl"]),
        .apt(["libcurl4-openssl-dev"])
    ],
    products: [
        // Products define the executables and libraries produced by a package, and make them visible to other packages.
        .library(
            name: "cURL",
            targets: ["cURL"]
        )
    ],
    targets: [
        .target(name: "cURL")
    ]
)
