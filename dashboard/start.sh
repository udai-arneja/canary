#!/bin/bash

# Start script for the AI Cyber Attack Monitoring Dashboard

echo "🚀 Starting AI Cyber Attack Monitoring Dashboard..."
echo ""

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker first."
    exit 1
fi

# Start services
echo "📦 Starting Docker containers..."
docker-compose up --build -d dashboard-backend dashboard

echo ""
echo "✅ Services started!"
echo ""
echo "📍 Access points:"
echo "   - Frontend Dashboard: http://localhost:3000"
echo "   - Backend API: http://localhost:8000"
echo "   - API Documentation: http://localhost:8000/docs"
echo ""
echo "💡 To generate test data, run:"
echo "   pip install requests"
echo "   python dashboard/backend/test_data.py 50"
echo ""
echo "🛑 To stop services, run:"
echo "   docker-compose down"

