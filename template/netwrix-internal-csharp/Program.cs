// Copyright (c) OpenFaaS Ltd 2024. All rights reserved.
// Licensed under the MIT license. See LICENSE file in the project root for full license information.

using function;

var builder = WebApplication.CreateBuilder(new WebApplicationOptions {
    WebRootPath = "static"
});

Handler.MapServices(builder.Services);

var app = builder.Build();

Handler.MapEndpoints(app);

app.Run("http://127.0.0.1:3000");
