// swift-tools-version: 5.7

///
import PackageDescription

///
let package = Package(
    name: "OSErrorModule",
    products: [
        .library(
            name: "OSErrorModule",
            targets: ["OSErrorModule"]
        ),
    ],
    dependencies: [],
    targets: [
        .target(
            name: "OSErrorModule",
            dependencies: []
        ),
        .testTarget(
            name: "OSErrorModule-tests",
            dependencies: ["OSErrorModule"]
        ),
    ]
)
