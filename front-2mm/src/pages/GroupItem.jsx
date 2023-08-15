import React from "react";
import { useNavigate } from "react-router-dom";
import styled from "styled-components";
import { useState } from "react";
import { useEffect } from "react";
import axios from "axios";

const Box = styled.div`
  position: relative;
  margin: auto;
  margin-bottom: -60px;
`;
const SettingBtn = styled.button`
  position: relative;
  top: -100px;
  left: 300px;
  width: 30px;
  height: 30px;
  background: url("${process.env.PUBLIC_URL}/images/settingbtn.svg");
  background-size: cover;
  border: none;
`;
const GroupTitle = styled.div`
  position: relative;
  top: -60px;
  left: 10px;
  color: #fff;
  font-family: SUIT;
  font-size: 22.34px;
  font-style: normal;
  font-weight: 700;
  line-height: normal;
`;
const Personnel = styled.div`
  position: relative;
  top: -50px;
  left: 10px;
  color: #fff;
  font-family: SUIT;
  font-size: 12px;
  font-style: normal;
  font-weight: 400;
  line-height: normal;
`;

// 해당 그룹의 이미지 불러오기.. get할때 그룹으로 get. 전체 말고
//code는 전달받은 것
const GroupItem = ({ code }) => {
  const navigate = useNavigate();

  const goGroupHome = () => {
    localStorage.setItem("code", code); // 해당 그룹으로 이동 시 코드 설정!!
    navigate(`/GroupHome`, { state: { code } }); // user_id, post_id read에 전달. 원래는 뒤에 ${postID}
  };
  const goGroupDetail = () => {
    navigate(`/GroupDetail`, { state: { code } }); // user_id, post_id read에 전달. 원래는 뒤에 ${postID}
  };

  // 그룹 상세 정보 불러오기
  const [group, setGroup] = useState(null);
  const [users, setUsers] = useState([]); // 추가
  const [postLoading, setPostLoading] = useState(true);

  console.log(code); // 코드 잘 전달됐는지 확인
  useEffect(() => {
    const fetchData = async () => {
      setPostLoading(true);
      try {
        // API 호출
        const response = await axios.get(
          `http://127.0.0.1:8000/group/${code}/`
        );
        setGroup(response.data);
        setUsers(response.data.user); // users배열에 저장 추가
      } catch (error) {
        console.error("Error fetching data:", error);
      }
      setPostLoading(false); // 로딩 상태 변경
    };
    fetchData(); // fetchData 함수 호출 (데이터를 서버에서 가져옴)
  }, []); // invitecode가 변경될 때마다 데이터를 다시 불러오도록

  if (postLoading) {
    return <div>대기중...</div>;
  }
  //사용자 몇명인지
  const userCount = users.length; // 사용자 수 구하기

  return (
    <>
      {group && (
        <Box onClick={goGroupHome}>
          <img
            style={{
              display: "block",
              margin: "auto",
              width: "346px",
              height: "175px",
              borderRadius: "17.76px",
              filter: "brightness(60%)",
            }}
            src={`http://127.0.0.1:8000${group.profile}`}
          />
        </Box>
      )}
      <SettingBtn onClick={goGroupDetail}></SettingBtn>
      <GroupTitle>{group && group.name}</GroupTitle>
      <Personnel>인원 {userCount}명</Personnel>
    </>
  );
};

export default GroupItem;
