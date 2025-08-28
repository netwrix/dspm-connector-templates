class Handler
  def run(body, headers, context = nil)
    # Example implementation - replace with actual handler logic
    response_data = {
      statusCode: 200,
      body: { message: "Hello from Netwrix Ruby handler" }
    }

    # Return the response data as-is for processing by the main handler
    return response_data, nil, nil
  end
end
