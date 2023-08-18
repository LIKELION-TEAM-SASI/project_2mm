import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useLocation } from "react-router-dom";
import { useEffect } from "react";
import axios from "axios";
const BACKEND_URL =
  "https://uuju.pythonanywhere.com" || "http://127.0.0.1:8000";

const Container = styled.div`
  position: relative;
  margin: 30px 0;
  max-width: 375px;
  height: 740px;
  background: #fff;
  border: 1px solid gray;
  margin: 30px auto;
  display: flex;
  flex-direction: column;
  justify-content: center;
  align-items: center;

  @media screen and (max-width: 768px) {
    width: 100%;
    padding-left: 0rem;
    padding-right: 0rem;
  }
`;
const GroupImage = styled.div`
  position: relative;
  margin-top: 0px;
  line-height: normal;
  display: flex;
  flex-direction: column;
  align-items: center;
  border-radius: 0px 0px 17.76px 17.76px;
  width: 375px;
  height: 200px;
`;
const GroupTitle = styled.div`
  position: absolute;
  margin-top: 80px;
  display: inline-block;
  color: #fff;
  font-family: SUIT;
  font-size: 30px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  border: none;
  background: none;
  text-align: center;
`;

const StickyBox = styled.div`
  position: sticky;
  top: 0;
`;
const BoxZone = styled.div`
  position: relative;
  height: 370px;
  margin: auto;
  overflow-y: scroll;
  overflow-x: hidden;
  &::-webkit-scrollbar {
    /* WebKit 브라우저의 스크롤바를 숨김 */
    width: 0;
    background: transparent;
  }
`;

const Box = styled.div`
  position: relative;
  margin-bottom: 10px;
  width: 340px;
  height: 70px;
  display: flex;
  flex-direction: vertical;
  align-items: center;
  justify-content: left;
`;

const ProfileImg = styled.div`
  position: relative;
  display: inline-block;
  margin-left: 10px;
  width: 50px;
  height: 50px;
  border-radius: 25px; /* 반지름을 width와 height의 절반으로 설정 */
  overflow: hidden;
`;
const NameText = styled.div`
  position: relative;
  display: inline-block;
  margin-left: 10px;
  color: #000;
  font-family: Inter;
  font-size: 15.188px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
`;

const AddText = styled.div`
  position: relative;
  display: inline-block;
  margin-left: 10px;
  color: #0057ff;
  font-family: Inter;
  font-size: 15.188px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  border: none;
  background: none;
`;
const DeleteBtn = styled.button`
  position: relative;
  display: flex;
  width: 330px;
  height: 78px;
  margin-bottom: 15px;
  padding: 27px 90px 26px 90px;
  justify-content: center;
  align-items: center;
  flex-shrink: 0;
  border-radius: 10px;
  border: 2px solid #0057ff;
  color: #0057ff;
  font-family: SUIT;
  font-size: 16px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
  background: none;
`;

// 가족 구성원 컴포넌트
// const FamilyBox = () => {
//   return (
//     <>
//       {/* 사용자 목록 출력 반복문으로 */}
//       {users.map((userObj) => (
//         <Box key={userObj.user}>
//           <ProfileImg>
//             <img
//               style={{ width: "100%", height: "100%", objectFit: "cover" }}
//               src={`http://127.0.0.1:8000${userObj.profile}`}
//             />
//           </ProfileImg>
//           <NameText>{userObj.user}</NameText>
//         </Box>
//       ))}
//     </>
//   );
// };

const GroupDetail = () => {
  // 이 페이지에서 수정 삭제 구현해야 함
  const navigate = useNavigate();

  const gotoAddMember = () => {
    // 멤버 추가하기 페이지로 이동 (임시)
    // 여기로 이동하고 끝이 맞나? 아님 추가 페이지를 하나 더 만들어야 됨?
    navigate("/AddFamily");
  };

  // 그룹 상세 정보 불러오기 추가
  const [group, setGroup] = useState(null);
  const [users, setUsers] = useState([]); // 추가
  const [user, setUser] = useState([]); // 추가
  const [postLoading, setPostLoading] = useState(true);

  // 전에 페이지에서 그룹 코드 받아오기
  const location = useLocation();
  // 이전 페이지에서 전달된 초대코드
  const { code } = location.state; // code 무조건 {}로 묶어야함!!
  console.log(code);

  useEffect(() => {
    const fetchData = async () => {
      setPostLoading(true);
      try {
        // API 호출
        const response = await axios.get(`${BACKEND_URL}/group/${code}/`);
        setGroup(response.data);
        setUsers(response.data.user); // users배열에 저장 추가
        console.log("유저 아이디: " + users);
      } catch (error) {
        console.error("Error fetching data:", error);
      }
      setPostLoading(false); // 로딩 상태 변경
    };
    fetchData(); // fetchData 함수 호출 (데이터를 서버에서 가져옴)
  }, [code]); // invitecode가 변경될 때마다 데이터를 다시 불러오도록

  if (postLoading) {
    return <div>대기중...</div>;
  }

  // 모임삭제하기 기능 추가
  const onSubmit = async () => {
    try {
      //const token = localStorage.getItem("token");
      // const headers = { Authorization: `Token ${token}` };
      //const code = localStorage.getItem("code"); // 이전 페이지에서 전달된 그룹코드
      // 이전 페이지에서 전달받은 코드를 불러와야 함. 그래야 클릭한 모임이 삭제됨 로컬스토리지에서 불러오지x
      axios
        .delete(`${BACKEND_URL}/group/${code}/`)
        .then((res) => {
          console.log(res);
          setGroup(group.filter((e) => group.code !== e.code)); // texts 배열 업데이트해서 해당 text.id와 일치하지 않는 데이터만 남도록 필터링
        })
        .catch((error) => {
          console.log(error);
        });

      navigate("/Home"); // 삭제버튼 누르면 홈으로
    } catch (error) {
      console.error("Error delete:", error);
    }
  };

  return (
    <Container>
      <StickyBox>
        <GroupImage>
          {group && group.profile && (
            <img
              style={{
                width: "100%",
                height: "100%",
                objectFit: "cover",
                borderRadius: "0px 0px 17.76px 17.76px",
                filter: "brightness(60%)",
              }}
              src={`${BACKEND_URL}${group.profile}`}
            />
          )}
          <GroupTitle>{group && group.name}</GroupTitle>
        </GroupImage>
      </StickyBox>
      <BoxZone>
        {/* 사용자 목록 출력 반복문으로 */}
        {users.map((userObj) => (
          <Box key={userObj.id}>
            <ProfileImg>
              <img
                style={{ width: "100%", height: "100%", objectFit: "cover" }}
                src={`${BACKEND_URL}${userObj.profile}`}
              />
            </ProfileImg>
            <NameText>{userObj.username}</NameText>
          </Box>
        ))}
        {/* 추가 페이지로 이동하는 박스 */}
        <Box onClick={gotoAddMember}>
          <ProfileImg>
            <img
              src={`${BACKEND_URL}/images/addcircle.svg`}
              style={{ width: "100%", height: "100%", objectFit: "cover" }}
            />
          </ProfileImg>
          <AddText onClick={gotoAddMember}>멤버 추가하기</AddText>
        </Box>
      </BoxZone>
      <DeleteBtn onClick={onSubmit}>모임 삭제하기</DeleteBtn>
    </Container>
  );
};

export default GroupDetail;
