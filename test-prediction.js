// Simple test script to verify database operations
const User = require('./models/User');
const Match = require('./models/Match');
const Prediction = require('./models/Prediction');

async function testDatabase() {
    try {
        console.log('🧪 Testing database operations...\n');

        // Test 1: Get all matches
        console.log('1. Testing Match.getAll()...');
        const matches = await Match.getAll();
        console.log(`✅ Found ${matches.length} matches`);
        if (matches.length > 0) {
            console.log(`   First match: ${matches[0].team_a} vs ${matches[0].team_b}`);
        }

        // Test 2: Create a test user
        console.log('\n2. Testing User.create()...');
        const testUser = await User.create({
            discordId: 'test_123',
            username: 'TestUser#0001',
            avatarUrl: null
        });
        console.log(`✅ Created user: ${testUser.username} (ID: ${testUser.id})`);

        // Test 3: Create a prediction
        if (matches.length > 0) {
            console.log('\n3. Testing Prediction.create()...');
            const prediction = await Prediction.create({
                userId: testUser.id,
                matchId: matches[0].id,
                predictedWinner: matches[0].team_a
            });
            console.log(`✅ Created prediction: ${prediction.predicted_winner} for match ${prediction.match_id}`);
        }

        // Test 4: Get updated match with predictions
        console.log('\n4. Testing updated match data...');
        const updatedMatches = await Match.getAll();
        const firstMatch = updatedMatches[0];
        console.log(`✅ Match now has ${firstMatch.total_predictions} prediction(s)`);
        console.log(`   ${firstMatch.team_a}: ${firstMatch.votes_team_a} votes (${firstMatch.percent_team_a}%)`);
        console.log(`   ${firstMatch.team_b}: ${firstMatch.votes_team_b} votes (${firstMatch.percent_team_b}%)`);

        console.log('\n🎉 All tests passed! Database is working correctly.');

    } catch (error) {
        console.error('❌ Test failed:', error);
    }
}

// Run tests
testDatabase();
